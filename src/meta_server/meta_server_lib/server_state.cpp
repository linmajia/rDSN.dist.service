/*

 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 * 
 * -=- Robust Distributed System Nucleus (rDSN) -=- 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * Description:
 *     the meta server's server_state, impl file
 *
 * Revision history:
 *     xxxx-xx-xx, author, first version
 *     2016-04-25, Weijie Sun(sunweijie at xiaomi.com), refactor
 */

# include <dsn/utility/factory_store.h>
# include <dsn/cpp/clientlet.h>
# include <sstream>
# include <cinttypes>
# include <string>
# include <exception>
# include <cstring>
# include <chrono>
# include <functional>
# include <new>
# include <utility>

# include "meta_service.h"
# include "server_state.h"
# include "server_load_balancer.h"

# ifdef __TITLE__
# undef __TITLE__
# endif
# define __TITLE__ "meta.server.state"

# include "dump_file.h"

using namespace dsn;

namespace dsn { namespace replication {

static bool is_node_being_restored(config_type::type type,
                                   const rpc_address& request_node,
                                   const rpc_address& member_node)
{
    return request_node == member_node &&
           (type == config_type::CT_ASSIGN_PRIMARY ||
            type == config_type::CT_UPGRADE_TO_PRIMARY ||
            type == config_type::CT_UPGRADE_TO_SECONDARY);
}

static bool is_valid_stateful_partition_config(const configuration_update_request& request)
{
    const partition_configuration& config = request.config;
    if (!config.primary.is_invalid() &&
        std::find(config.last_drops.begin(), config.last_drops.end(), config.primary) !=
            config.last_drops.end() &&
        !is_node_being_restored(request.type, request.node, config.primary))
    {
        return false;
    }

    for (const auto& secondary : config.secondaries)
    {
        if (std::find(config.last_drops.begin(), config.last_drops.end(), secondary) !=
            config.last_drops.end() &&
            !is_node_being_restored(request.type, request.node, secondary))
        {
            return false;
        }
    }

    // The request's target node must not already be present in last_drops. For a
    // removal/downgrade request (CT_REMOVE / CT_DOWNGRADE_TO_INACTIVE),
    // server_state::on_update_configuration hands the request to
    // maintain_drops(..., is_add=false), which asserts (dassert -> coredump, aborting
    // the meta server) if the node is already in the drop set. A malicious or corrupt
    // replica can craft a request whose node is the current primary/secondary (so
    // request_check passes) yet is also listed in config.last_drops, while the new
    // config's own primary/secondaries are not -- slipping past the checks above and
    // driving the assert with unauthenticated network input (CWE-617). Reject it here.
    // Restore requests legitimately re-add a dropped node, so honor the same
    // is_node_being_restored exemption used for primary/secondaries above; those types
    // call maintain_drops(..., is_add=true), which never asserts. Honest removal
    // requests never list the node being removed in last_drops (maintain_drops is what
    // adds it), so this check is behavior-preserving.
    if (!request.node.is_invalid() &&
        std::find(config.last_drops.begin(), config.last_drops.end(), request.node) !=
            config.last_drops.end() &&
        !is_node_being_restored(request.type, request.node, request.node))
    {
        return false;
    }

    return true;
}

template<typename TResponse>
static inline void reply_message(meta_service* svc, dsn_message_t request_msg, TResponse&& response_data)
{
    dsn_message_t response_msg = dsn_msg_create_response(request_msg);
    dsn::marshall(response_msg, response_data);
    svc->reply_message(request_msg, response_msg);
}

template<typename TResponse>
static inline bool reply_service_not_active_if_stopped(meta_service* svc,
                                                       dsn_message_t request_msg)
{
    if (!svc->is_stopped())
    {
        return false;
    }

    TResponse response;
    response.err = ERR_SERVICE_NOT_ACTIVE;
    reply_message(svc, request_msg, response);
    dsn_msg_release_ref(request_msg);
    return true;
}

class cancellable_retry
{
public:
    cancellable_retry(std::function<void()> callback, std::function<void()> on_cancel)
        : _callback(std::move(callback)), _on_cancel(std::move(on_cancel)), _consumed(false)
    {
    }

    ~cancellable_retry()
    {
        if (!_consumed.exchange(true, std::memory_order_acq_rel))
        {
            _on_cancel();
        }
    }

    void run()
    {
        if (!_consumed.exchange(true, std::memory_order_acq_rel))
        {
            _callback();
        }
    }

    void disarm() { _consumed.store(true, std::memory_order_release); }

private:
    std::function<void()> _callback;
    std::function<void()> _on_cancel;
    std::atomic<bool> _consumed;
};

template <typename TCallback, typename TCancel>
static task_ptr enqueue_cancellable_retry(clientlet* tracker,
                                          TCallback&& callback,
                                          TCancel&& on_cancel,
                                          std::chrono::milliseconds delay)
{
    std::shared_ptr<cancellable_retry> retry;
    try
    {
        retry = std::make_shared<cancellable_retry>(
            std::forward<TCallback>(callback), std::forward<TCancel>(on_cancel));
        auto task = tasking::create_task(
            LPC_META_STATE_HIGH, tracker, [retry] { retry->run(); }, 0);
        if (task == nullptr)
        {
            retry->disarm();
            return nullptr;
        }

        task->enqueue(delay);
        return task;
    }
    catch (const std::bad_alloc&)
    {
        if (retry != nullptr)
        {
            retry->disarm();
        }
        derror("allocate delayed meta-state retry failed");
        return nullptr;
    }
}

template<typename TResponse>
static void cancel_pending_request(meta_service* svc, dsn_message_t request_msg)
{
    TResponse response;
    response.err = svc->is_stopped() ? ERR_SERVICE_NOT_ACTIVE : ERR_TRY_AGAIN;
    dsn_message_t response_msg = dsn_msg_create_response(request_msg);
    if (response_msg == nullptr)
    {
        derror("create response for cancelled request failed");
    }
    else
    {
        error_code err = dsn::try_marshall(response_msg, response);
        dsn_error_t reply_err =
            err == ERR_OK ? dsn_rpc_reply(response_msg) : dsn_rpc_reply(response_msg, err.get());
        if (reply_err != ERR_OK)
        {
            derror("reply cancelled request failed: %s", error_code(reply_err).to_string());
        }
    }
    dsn_msg_release_ref(request_msg);
}

server_state::server_state():
    _meta_svc(nullptr), _creating_apps_count(0), _dropping_apps_count(0),
    _cli_json_state_handle(nullptr), _cli_dump_handle(nullptr)
{
}

server_state::~server_state()
{
    cancel_retries();

    if (_cli_json_state_handle != nullptr)
    {
        dsn_cli_deregister(_cli_json_state_handle);
        _cli_json_state_handle = nullptr;
    }
    if (_cli_dump_handle != nullptr)
    {
        dsn_cli_deregister(_cli_dump_handle);
        _cli_dump_handle = nullptr;
    }
}

void server_state::cancel_retries()
{
    dsn_task_tracker_cancel_all(_retry_tasks.tracker());
}

void server_state::abort_pending_configuration_syncs()
{
    zauto_write_lock l(_lock);
    for (auto& app_entry : _all_apps)
    {
        std::shared_ptr<app_state>& app = app_entry.second;
        size_t partition_count =
            std::min(app->partitions.size(), app->helpers->contexts.size());
        for (size_t i = 0; i < partition_count; ++i)
        {
            config_context& context = app->helpers->contexts[i];
            if (context.stage == config_status::pending_remote_sync)
            {
                abort_configuration_sync(context, app->partitions[i]);
            }
        }
    }
}

void server_state::register_cli_commands()
{
    _cli_json_state_handle = dsn_cli_app_register(
        "info",
        "get info of nodes and apps on meta_server",
        "",
        this,
        &static_cli_json_state, &static_cli_json_state_cleanup);
    dassert(_cli_json_state_handle != nullptr, "register cil handler failed, maybe it has been registered");

    _cli_dump_handle = dsn_cli_app_register(
        "dump",
        "dump app_states of meta server to local file",
        "usage: -t|--target target_file",
        this,
        &static_cli_dump_app_states,
        &static_cli_dump_app_states_cleanup
        );
    dassert(_cli_dump_handle != nullptr, "register cli handler failed");
}

void server_state::initialize(meta_service *meta_svc, const std::string &apps_root)
{
    _meta_svc = meta_svc;
    _apps_root = apps_root;
}

bool server_state::spin_wait_creating(int timeout_seconds)
{
    while (_creating_apps_count.load() != 0 && (timeout_seconds==-1 || timeout_seconds>0)) {
        ddebug("there are (%d) apps still creating, just wait...", _creating_apps_count.load());
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (timeout_seconds > 0)
            --timeout_seconds;
    }
    return _creating_apps_count.load() == 0;
}

error_code server_state::dump_app_states(const char* local_path, const std::function<app_state* ()>& iterator)
{
    std::shared_ptr<dump_file> file = dump_file::open_file(local_path, true);
    if (file == nullptr) {
        derror("open file failed, file(%s)", local_path);
        return ERR_FILE_OPERATION_FAILED;
    }

    // append_buffer returns -1 when the underlying write fails (e.g. the disk is
    // full or hits an I/O error), and close() (below) reports a flush/close-time
    // write-back error. Those errors must abort the dump and be reported to the
    // caller; otherwise a truncated/corrupt dump would be silently reported as a
    // success and later fail to restore.
    if (file->append_buffer("binary", 6) != 0) {
        derror("dump to file(%s) failed: cannot write format header", local_path);
        return ERR_FILE_OPERATION_FAILED;
    }
    app_state* app;
    while ( (app = iterator())!=nullptr)
    {
        dassert(app->status==app_status::AS_AVAILABLE || app->status==app_status::AS_DROPPED, "invalid app status");
        binary_writer writer;
        dsn::marshall(writer, *app, DSF_THRIFT_BINARY);
        if (file->append_buffer(writer.get_buffer()) != 0) {
            derror("dump to file(%s) failed: cannot write state of app(%s)", local_path, app->app_name.c_str());
            return ERR_FILE_OPERATION_FAILED;
        }
        if (app_status::AS_AVAILABLE == app->status) {
            for (const partition_configuration& pc: app->partitions) {
                binary_writer writer;
                dsn::marshall(writer, pc, DSF_THRIFT_BINARY);
                if (file->append_buffer(writer.get_buffer()) != 0) {
                    derror("dump to file(%s) failed: cannot write a partition config of app(%s)", local_path, app->app_name.c_str());
                    return ERR_FILE_OPERATION_FAILED;
                }
            }
        }
    }
    // close() flushes remaining buffered data and closes the file, reporting a
    // write-back error (disk full / I/O) that stdio may surface only at flush or
    // close time. It must be checked here, before returning success: relying on
    // the destructor's fclose would surface such an error only after this
    // function had already returned ERR_OK, i.e. a truncated dump reported as a
    // successful one.
    if (file->close() != 0) {
        derror("dump to file(%s) failed: cannot flush/close the dump file", local_path);
        return ERR_FILE_OPERATION_FAILED;
    }
    return ERR_OK;
}

error_code server_state::dump_from_remote_storage(const char *local_path, bool sync_immediately)
{
    error_code ec;

    if (sync_immediately) {
        ec=sync_apps_from_remote_storage();
        if (ec == ERR_OBJECT_NOT_FOUND) {
            dwarn("remote storage is empty, just stop the dump");
            return ERR_OK;
        }
        else if (ec != ERR_OK){
            derror("sync from remote storage failed, err(%s)", ec.to_string());
            return ec;
        }
        else {
            spin_wait_creating();
        }
        auto iter_begin = _all_apps.begin();
        auto iter_end = _all_apps.end();
        return dump_app_states(local_path, [&iter_begin, &iter_end]()->app_state* {
            if (iter_begin == iter_end)
                return nullptr;
            app_state* result = iter_begin->second.get();
            ++iter_begin;
            return result;
        });
    }
    else {
        std::vector<app_state> snapshots;
        {
            zauto_read_lock l(_lock);
            if (_creating_apps_count.load()!=0 || _dropping_apps_count.load()!=0) {
                ddebug("there are %d creating apps && %d dropping apps, skip this dump", _creating_apps_count.load(), _dropping_apps_count.load());
                return ERR_INVALID_STATE;
            }
            snapshots.reserve(_all_apps.size());
            for (auto& app_pair: _all_apps)
                snapshots.push_back(*(app_pair.second));
        }
        auto iter_begin = snapshots.begin(), iter_end = snapshots.end();
        return dump_app_states(local_path, [&iter_begin, &iter_end]()->app_state* {
            if (iter_begin == iter_end)
                return nullptr;
            app_state* result = &(*iter_begin);
            ++iter_begin;
            return result;
        });
    }
}

error_code server_state::restore_from_local_storage(const char* local_path)
{
    error_code ec;

    std::shared_ptr<dump_file> file = dump_file::open_file(local_path, false);
    if (file == nullptr)
    {
        derror("open file failed, file(%s)", local_path);
        return ERR_FILE_OPERATION_FAILED;
    }

    _all_apps.clear();

    // The dump file is local on-disk metadata without a checksum. A truncated or corrupt
    // file (partial dump, media error) must fail this restore with an error instead of
    // aborting the whole meta-server. read_next_buffer returns 1 on a record, 0 at EOF and
    // -1 on a read error; unmarshall and app_state::create can throw std::out_of_range on a
    // short buffer or std::bad_alloc/std::length_error on a corrupt huge partition_count.
    blob data;
    if (file->read_next_buffer(data) != 1)
    {
        derror("restore from local storage failed: cannot read format header from %s", local_path);
        return ERR_INVALID_DATA;
    }
    if (data.length() < 6 || memcmp(data.data(), "binary", 6) != 0)
    {
        derror("restore from local storage failed: bad format header in %s", local_path);
        return ERR_INVALID_DATA;
    }

    try
    {
        while (true)
        {
            int ans = file->read_next_buffer(data);
            if (ans == -1)
            {
                derror("restore from local storage failed: read error in %s", local_path);
                _all_apps.clear();
                return ERR_INVALID_DATA;
            }
            if (ans == 0) //file end
                break;

            app_info info;
            binary_reader reader(data);
            unmarshall(reader, info, DSF_THRIFT_BINARY);
            std::shared_ptr<app_state> app = app_state::create(info);
            _all_apps.emplace(app->app_id, app);

            if (app->status == app_status::AS_AVAILABLE)
            {
                for (unsigned int i=0; i!=app->partition_count; ++i)
                {
                    ans = file->read_next_buffer(data);
                    if (ans != 1)
                    {
                        derror("restore from local storage failed: missing partition data, "
                               "gpid(%d.%u), appname(%s)", app->app_id, i, app->app_name.c_str());
                        _all_apps.clear();
                        return ERR_INVALID_DATA;
                    }
                    binary_reader reader(data);
                    unmarshall(reader, app->partitions[i], DSF_THRIFT_BINARY);
                    if (app->partitions[i].pid.get_partition_index() != (int)i)
                    {
                        derror("restore from local storage failed: incorrect partition data, "
                               "gpid(%d.%u), appname(%s)", app->app_id, i, app->app_name.c_str());
                        _all_apps.clear();
                        return ERR_INVALID_DATA;
                    }
                }
            }
        }
    }
    catch (const std::exception& ex)
    {
        derror("restore from local storage failed: corrupt metadata in %s, err = %s",
               local_path, ex.what());
        _all_apps.clear();
        return ERR_INVALID_DATA;
    }

    for (auto& iter: _all_apps)
        if (iter.second->status == app_status::AS_AVAILABLE)
            iter.second->status = app_status::AS_CREATING;

    ec = sync_apps_to_remote_storage();
    if (ec != ERR_OK) {
        _all_apps.clear();
        return ec;
    }
    spin_wait_creating();
    return ERR_OK;
}

error_code server_state::initialize_default_apps()
{
    const char* sections[10240];
    int total_sections;
    int used_sections = sizeof(sections)/sizeof(const char*);
    total_sections = dsn_config_get_all_sections(sections, &used_sections);
    dassert(total_sections == used_sections, "too many sections (>10240) defined in config files");
    ddebug("start to do initialize");

    app_info default_app;
    for (int i = 0; i < used_sections; i++)
    {
        if (strstr(sections[i], "meta_server.apps")==sections[i] || strcmp(sections[i], "replication.app")==0)
        {
            const char* s = sections[i];

            default_app.status = app_status::AS_CREATING;
            default_app.app_id = _all_apps.size() + 1;

            default_app.app_name = dsn_config_get_value_string(s, "app_name", "", "app name");
            default_app.app_type = dsn_config_get_value_string(s, "app_type", "", "app type-name");
            default_app.partition_count = (int)dsn_config_get_value_uint64(s, "partition_count", 1, "how many partitions the app should have");
            default_app.is_stateful = dsn_config_get_value_bool(s, "stateful", true, "whether this is a stateful app");
            default_app.max_replica_count = (int)dsn_config_get_value_uint64(s, "max_replica_count", 3, "max_replica count in app");
            //TODO: setup envs

            dassert(default_app.app_name.length() > 0, "'[%s] app_name' not specified", s);
            dassert(default_app.app_type.length() > 0, "'[%s] app_type' not specified", s);

            std::shared_ptr<app_state> app = app_state::create(default_app);
            _all_apps.emplace(app->app_id, app);
        }
    }

    error_code err = sync_apps_to_remote_storage();
    if (err != ERR_OK)
    {
        _all_apps.clear();
        return err;
    }
    return ERR_OK;
}

//caller should ensure all apps are creating or dropped
error_code server_state::sync_apps_to_remote_storage()
{
    _exist_apps.clear();
    for (auto& kv_pair: _all_apps) {
        if (kv_pair.second->status == app_status::AS_CREATING) {
            dassert(_exist_apps.find(kv_pair.second->app_name) == _exist_apps.end(), "");
            _exist_apps.emplace(kv_pair.second->app_name, kv_pair.second);
        }
    }
    _creating_apps_count.store(_exist_apps.size());

    // create cluster_root/apps node
    std::string& apps_path = _apps_root;
    error_code err;
    dist::meta_state_service* storage = _meta_svc->get_remote_storage();
    auto t = storage->create_node(apps_path, LPC_META_CALLBACK,
        [&err](error_code ec)
        { err = ec; }
    );
    t->wait();

    if (err != ERR_NODE_ALREADY_EXIST && err != ERR_OK)
    {
        derror("create root node /apps in meta store failed, err = %s",
            err.to_string());
        return err;
    }

    err = ERR_OK;
    clientlet tracker(1);
    for (auto& kv: _all_apps)
    {
        std::shared_ptr<app_state>& app = kv.second;
        std::string path = get_app_path(*app);

        dassert(app->status==app_status::AS_CREATING || app->status==app_status::AS_DROPPED, "invalid app status");
        blob value = app->encode_json_with_status(app_status::AS_CREATING==app->status? app_status::AS_AVAILABLE : app_status::AS_DROPPED);
        storage->create_node(path,
            LPC_META_CALLBACK,
            [&err, path](error_code ec)
            {
                if (ec != ERR_OK && ec != ERR_NODE_ALREADY_EXIST)
                {
                    dwarn("create app node failed, path(%s) reason(%s)", path.c_str(), ec.to_string());
                    err = ec;
                }
                else
                {
                    ddebug("create app node %s ok", path.c_str());
                }
            },
            value,
            &tracker);
    }
    dsn_task_tracker_wait_all(tracker.tracker());

    if (err != ERR_OK)
    {
        _exist_apps.clear();
        _creating_apps_count.store(0);
        return err;
    }
    for (auto& kv: _exist_apps)
    {
        std::shared_ptr<app_state>& app = kv.second;
        for (unsigned int i=0; i!=app->partition_count; ++i)
            init_app_partition_node(app, i);
    }
    return ERR_OK;
}

dsn::error_code server_state::sync_apps_from_remote_storage()
{
    dsn::error_code err;
    dsn::clientlet tracker(1);

    dist::meta_state_service* storage = _meta_svc->get_remote_storage();
    auto sync_partition = [this, storage, &err, &tracker](std::shared_ptr<app_state>& app, int partition_id, const std::string& partition_path)
    {
        storage->get_data(partition_path, LPC_META_CALLBACK,
            [this, app, partition_id, partition_path, &err](error_code ec, const blob& value) mutable
            {
                if (ec == ERR_OK)
                {
                    partition_configuration pc;
                    if (!dsn::json::json_forwarder<partition_configuration>::decode(value, pc))
                    {
                        derror("invalid partition json data from remote storage, path = %s", partition_path.c_str());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    if (pc.pid.get_app_id() != app->app_id || pc.pid.get_partition_index() != partition_id)
                    {
                        derror("invalid partition config from remote storage, path = %s", partition_path.c_str());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    // pc.secondaries is loaded from (semi-untrusted) remote storage and is
                    // consumed by initialize_node_state() and check_consistency(), both of which
                    // assert (always-on dassert -> coredump) that every endpoint is valid and
                    // registered in _nodes. A corrupt/hand-edited record can carry an invalid
                    // endpoint (e.g. a secondary serialized as the "invalid address" marker, which
                    // json_decode accepts for the primary's benefit), which would abort the meta
                    // server on recovery. For stateless apps this vector holds hosts() and pairs
                    // with last_drops as workers(), so we cannot silently drop entries without
                    // breaking the hosts().size()==workers().size() invariant; reject the whole
                    // record here through the same error channel as the pid check instead.
                    for (const dsn::rpc_address& ep : pc.secondaries)
                    {
                        if (ep.is_invalid())
                        {
                            derror("invalid secondary endpoint in partition config from remote storage, path = %s", partition_path.c_str());
                            err = ERR_INVALID_DATA;
                            return;
                        }
                    }
                    // last_drops is also loaded from (semi-untrusted) remote storage. check_consistency()
                    // enforces, via always-on dasserts, additional invariants over it that a corrupt or
                    // hand-edited record can violate, aborting the meta server on recovery. Mirror those
                    // exact invariants here and reject the whole record through the same error channel:
                    //   - stateful apps: neither the primary nor any secondary may also appear in last_drops.
                    //   - stateless apps: secondaries (hosts) and last_drops (workers) are paired, so their
                    //     sizes must match (partition_configuration_stateless asserts hosts()==workers() size).
                    if (app->is_stateful)
                    {
                        if (!pc.primary.is_invalid()
                            && std::find(pc.last_drops.begin(), pc.last_drops.end(), pc.primary) != pc.last_drops.end())
                        {
                            derror("primary endpoint also present in last_drops in partition config from remote storage, path = %s", partition_path.c_str());
                            err = ERR_INVALID_DATA;
                            return;
                        }
                        for (const dsn::rpc_address& ep : pc.secondaries)
                        {
                            if (std::find(pc.last_drops.begin(), pc.last_drops.end(), ep) != pc.last_drops.end())
                            {
                                derror("secondary endpoint also present in last_drops in partition config from remote storage, path = %s", partition_path.c_str());
                                err = ERR_INVALID_DATA;
                                return;
                            }
                        }
                    }
                    else
                    {
                        if (pc.secondaries.size() != pc.last_drops.size())
                        {
                            derror("stateless partition config from remote storage has mismatched secondaries(%d)/last_drops(%d) sizes, path = %s",
                                (int)pc.secondaries.size(), (int)pc.last_drops.size(), partition_path.c_str());
                            err = ERR_INVALID_DATA;
                            return;
                        }
                    }
                    {
                        zauto_write_lock l(_lock);
                        app->partitions[partition_id] = pc;
                    }
                    inc_creating_app_available_partitions(app);
                }
                else if (ec == ERR_OBJECT_NOT_FOUND)
                {
                    dwarn("partition node %s not exist on remote storage, may half create before", partition_path.c_str());
                    init_app_partition_node(app, partition_id);
                }
                else
                {
                    derror("get partition node failed, reason(%s)", ec.to_string());
                    err = ec;
                }
            },
            &tracker
        );
    };

    auto sync_app = [&](const std::string& app_path)
    {
        storage->get_data(app_path, LPC_META_CALLBACK,
            [this, app_path, &err, &sync_partition](error_code ec, const blob& value)
            {
                if (ec == ERR_OK)
                {
                    app_info info;
                    if (!dsn::json::json_forwarder<app_info>::decode(value, info))
                    {
                        derror("invalid app json data from remote storage, path = %s", app_path.c_str());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    if (info.status != app_status::AS_AVAILABLE && info.status != app_status::AS_DROPPED)
                    {
                        derror("invalid app status in remote storage, path = %s", app_path.c_str());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    if (info.partition_count <= 0)
                    {
                        derror("invalid partition_count(%d) in remote storage, path = %s",
                            info.partition_count, app_path.c_str());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    std::shared_ptr<app_state> app;
                    try
                    {
                        // partition_count comes from (semi-untrusted) remote storage;
                        // a corrupt huge/negative value makes app_state allocate its
                        // partition vector and throw std::bad_alloc/std::length_error.
                        // Report it as invalid data instead of aborting the meta server.
                        app = app_state::create(info);
                    }
                    catch (const std::exception& ex)
                    {
                        derror("invalid app(%s) in remote storage: cannot allocate %d "
                               "partitions, err: %s", info.app_name.c_str(),
                               info.partition_count, ex.what());
                        err = ERR_INVALID_DATA;
                        return;
                    }
                    {
                        zauto_write_lock l(_lock);
                        _all_apps.emplace(app->app_id, app);
                        if (app->status == app_status::AS_AVAILABLE) {
                            _exist_apps.emplace(app->app_name, app);
                        }
                        else
                            return;
                    }

                    app->status = app_status::AS_CREATING;
                    ++_creating_apps_count;
                    for (int i = 0; i < app->partition_count; i++)
                    {
                        std::string partition_path = app_path + "/" + std::to_string(i);
                        sync_partition(app, i, partition_path);
                    }
                }
                else
                {
                    derror("get app info from meta state service failed, path = %s, err = %s",
                        app_path.c_str(), ec.to_string());
                    err = ec;
                }
            },
            &tracker
        );
    };

    _all_apps.clear();
    _exist_apps.clear();
    _creating_apps_count.store(0);
    storage->get_children(_apps_root, LPC_META_CALLBACK,
        [&](error_code ec, const std::vector<std::string>& apps)
        {
            if (ec == ERR_OK)
            {
                for (const auto& appid_str : apps) {
                    sync_app(_apps_root + "/" + appid_str);
                }
            }
            else
            {
                derror("get app list from meta state service failed, path = %s, err = %s",
                    _apps_root.c_str(), ec.to_string());
                err = ec;
            }
        },
        &tracker
    );
    dsn_task_tracker_wait_all(tracker.tracker());
    if (err == ERR_OK)
    {
        return _all_apps.empty()?ERR_OBJECT_NOT_FOUND:ERR_OK;
    }
    return err;
}

void server_state::initialize_node_state()
{
    zauto_write_lock l(_lock);
    for (auto& app_pair: _exist_apps) {
        app_state& app = *(app_pair.second);
        for (partition_configuration& pc: app.partitions) {
            if (!pc.primary.is_invalid()) {
                _nodes[pc.primary].primaries.insert(pc.pid);
                _nodes[pc.primary].partitions.insert(pc.pid);
            }
            for (auto& ep: pc.secondaries) {
                dassert(!ep.is_invalid(), "");
                _nodes[ep].partitions.insert(pc.pid);
            }
        }
    }
    for (auto& node: _nodes) {
        node.second.address = node.first;
        node.second.is_alive = true;
    }
    for (auto& app_pair: _exist_apps) {
        app_state& app = *(app_pair.second);
        for (const partition_configuration& pc: app.partitions) {
            check_consistency(pc.pid);
        }
    }
}

error_code server_state::initialize_data_structure()
{
    error_code err = sync_apps_from_remote_storage();
    if (err == ERR_OBJECT_NOT_FOUND)
    {
        ddebug("can't find apps from remote storage, start to create default apps");
        err = initialize_default_apps();
    }
    else if (err == ERR_OK)
    {
        ddebug("sync apps from remote storage ok, get %d apps, init the node state accordingly", (int)_all_apps.size());
        initialize_node_state();
    }
    return err;
}

void server_state::set_config_change_subscriber_for_test(config_change_subscriber subscriber)
{
    _config_change_subscriber = subscriber;
}

void server_state::set_replica_migration_subscriber_for_test(replica_migration_subscriber subscriber)
{
    _replica_migration_subscriber = subscriber;
}

// client => meta server
void server_state::query_configuration_by_node(const configuration_query_by_node_request& request, /*out*/ configuration_query_by_node_response& response)
{
    zauto_read_lock l(_lock);
    auto it = _nodes.find(request.node);
    if (it == _nodes.end())
    {
        response.err = ERR_OBJECT_NOT_FOUND;
    }
    else
    {
        response.err = ERR_OK;
        response.partitions.resize(it->second.partitions.size());
        unsigned i = 0;
        for (auto& p: it->second.partitions)
        {
            std::shared_ptr<app_state> app = get_app(p.get_app_id());
            dassert(app != nullptr, "");
            response.partitions[i].config = app->partitions[p.get_partition_index()];
            response.partitions[i].info = *app;
            response.partitions[i].host_node = request.node;            
            ++i;
        }
    }
}

// partition server => meta server
// this is done in meta_state_thread_pool
void server_state::on_config_sync(dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_query_by_node_response>(
            _meta_svc, msg))
    {
        return;
    }

    configuration_query_by_node_request request;
    configuration_query_by_node_response response;

    auto decode_err = dsn::try_unmarshall(msg, request);
    if (decode_err != ERR_OK)
    {
        derror("invalid config sync request: %s", decode_err.to_string());
        response.err = decode_err;
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
        return;
    }

    bool reject_this_request = false;
    {
        zauto_read_lock l(_lock);
        auto it = _nodes.find(request.node);
        if (it == _nodes.end())
            response.err = ERR_OBJECT_NOT_FOUND;
        else
        {
            response.err = ERR_OK;
            response.partitions.resize(it->second.partitions.size());
            unsigned i = 0;
            for (auto& p: it->second.partitions)
            {
                std::shared_ptr<app_state> app = get_app(p.get_app_id());
                dassert(app != nullptr, "");
                config_context& cc = app->helpers->contexts[p.get_partition_index()];

                // config sync need the newest data to keep the perfect FD,
                // so if the syncing config is related to the node, we may need to reject this request
                if (cc.stage == config_status::pending_remote_sync)
                {
                    configuration_update_request* req = cc.pending_sync_request.get();
                    if (req->node == request.node)
                        break;
                }

                response.partitions[i].config = app->partitions[p.get_partition_index()];
                response.partitions[i].info = *app;
                ++i;
            }

            if (i < response.partitions.size()) {
                reject_this_request = true;
            }
        }
    }

    if (reject_this_request)
    {
        response.err = ERR_BUSY;
        response.partitions.clear();
    }
    reply_message(_meta_svc, msg, response);
    dsn_msg_release_ref(msg);
}

bool server_state::query_configuration_by_gpid(dsn::gpid id, /*out*/partition_configuration& config)
{
    zauto_read_lock l(_lock);
    const partition_configuration* pc = get_config(_all_apps, id);
    if (pc != nullptr) {
        config = *pc;
        return true;
    }
    return false;
}

void server_state::query_configuration_by_index(const configuration_query_by_index_request& request, /*out*/ configuration_query_by_index_response& response)
{
    zauto_read_lock l(_lock);
    auto iter = _exist_apps.find(request.app_name.c_str());
    if (iter == _exist_apps.end()) {
        response.err = ERR_OBJECT_NOT_FOUND;
        return;
    }

    std::shared_ptr<app_state>& app = iter->second;
    if ( app->status != app_status::AS_AVAILABLE ) {
        dassert(app->status==app_status::AS_CREATING || app->status==app_status::AS_DROPPING, "invalid status in exist app");
        response.err = (app->status==app_status::AS_CREATING?ERR_BUSY_CREATING:ERR_BUSY_DROPPING);
        return;
    }

    response.err = ERR_OK;
    response.app_id = app->app_id;
    response.partition_count = app->partition_count;
    response.is_stateful = app->is_stateful;

    for (const int32_t& index: request.partition_indices) {
        if (index>=0 && index<app->partitions.size())
            response.partitions.push_back( app->partitions[index]);
    }
    if (response.partitions.empty())
        response.partitions = app->partitions;
}

void server_state::init_app_partition_node(std::shared_ptr<app_state>& app, int pidx)
{
    if (_meta_svc->is_stopped())
    {
        return;
    }

    auto on_create_app_partition = [this, pidx, app](error_code ec) mutable
    {
        if (_meta_svc->is_stopped())
        {
            return;
        }

        dinfo("create partition node: gpid(%d.%d), result: %s", app->app_id, pidx, ec.to_string());
        if (ERR_OK==ec || ERR_NODE_ALREADY_EXIST==ec)
        {
            inc_creating_app_available_partitions(app);
        }
        else if (ERR_OBJECT_NOT_FOUND == ec || ERR_INVALID_PARAMETERS == ec || ERR_INCONSISTENT_STATE == ec)
        {
            // Permanent remote-storage errors: retrying the same create-node can
            // never succeed, so fail-stop instead of looping forever.
            dassert(false, "we can't handle this error in init app partition nodes err(%s), gpid(%d.%d)", ec.to_string(), app->app_id, pidx);
        }
        else
        {
            // Transient remote-storage error -- ERR_TIMEOUT (connection loss /
            // operation timeout / session expiry) or ERR_ZOOKEEPER_OPERATION
            // (e.g. a marshalling failure under memory pressure): retry this
            // idempotent create-node instead of aborting the whole meta server.
            dwarn("create partition node failed, gpid(%d.%d), err(%s), retry later", app->app_id, pidx, ec.to_string());
            //TODO: add parameter of the retry time interval in config file
            task_ptr retry_task = enqueue_cancellable_retry(
                &_retry_tasks,
                std::bind(&server_state::init_app_partition_node, this, app, pidx),
                [] {},
                std::chrono::milliseconds(1000));
            if (retry_task == nullptr)
            {
                derror("enqueue partition-node retry failed, gpid(%d.%d)",
                       app->app_id,
                       pidx);
                if (!_meta_svc->is_stopped())
                {
                    init_app_partition_node(app, pidx);
                }
            }
        }
    };

    std::string app_partition_path = get_partition_path(*app, pidx);
    dsn::blob value = dsn::json::json_forwarder<partition_configuration>::encode(app->partitions[pidx]);
    _meta_svc->get_remote_storage()->create_node(app_partition_path,
        LPC_META_STATE_HIGH,
        on_create_app_partition,
        value,
        _meta_svc
    );
}

void server_state::do_app_create(std::shared_ptr<app_state>& app, dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_create_app_response>(
            _meta_svc, msg))
    {
        return;
    }

    auto on_create_app_root = [this, msg, app](error_code ec) mutable
    {
        if (reply_service_not_active_if_stopped<configuration_create_app_response>(
                _meta_svc, msg))
        {
            return;
        }

        configuration_create_app_response resp;
        if (ERR_OK==ec || ERR_NODE_ALREADY_EXIST==ec)
        {
            dinfo("create app on storage service ok, name: %s, appid %" PRId32 "", app->app_name.c_str(), app->app_id);
            resp.appid = app->app_id;
            resp.err = ERR_OK;
            reply_message(_meta_svc, msg, resp);
            dsn_msg_release_ref(msg);
            for (unsigned int i=0; i!=app->partition_count; ++i)
            {
                init_app_partition_node(app, i);
            }
        }
        else if (ERR_OBJECT_NOT_FOUND == ec || ERR_INVALID_PARAMETERS == ec || ERR_INCONSISTENT_STATE == ec)
        {
            // Permanent remote-storage errors: retrying the same create-node can
            // never succeed, so fail-stop instead of looping forever.
            dassert(false, "we can't handle this right now, err(%s)", ec.to_string());
        }
        else
        {
            // Transient remote-storage error -- the storage is temporarily
            // unavailable (ERR_TIMEOUT) or failed with ERR_ZOOKEEPER_OPERATION
            // (e.g. a marshalling failure under memory pressure). Retry instead of
            // aborting the whole meta server; the create is idempotent
            // (ERR_NODE_ALREADY_EXIST is treated as success).
            dwarn("create app on storage service failed, name: %s, err(%s), continue to create later", app->app_name.c_str(), ec.to_string());
            task_ptr retry_task = enqueue_cancellable_retry(
                &_retry_tasks,
                std::bind(&server_state::do_app_create, this, app, msg),
                [this, msg] {
                    cancel_pending_request<configuration_create_app_response>(_meta_svc, msg);
                },
                std::chrono::seconds(1));
            if (retry_task == nullptr)
            {
                derror("enqueue app-create retry failed, name: %s, retry immediately",
                       app->app_name.c_str());
                do_app_create(app, msg);
            }
        }
    };

    std::string app_dir = get_app_path(*app);
    blob value = app->encode_json_with_status(app_status::AS_AVAILABLE);
    _meta_svc->get_remote_storage()->create_node(
        app_dir,
        LPC_META_STATE_HIGH,
        on_create_app_root,
        value,
        _meta_svc
    );
}

void server_state::create_app(dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_create_app_response>(
            _meta_svc, msg))
    {
        return;
    }

    configuration_create_app_request request;
    configuration_create_app_response response;
    std::shared_ptr<app_state> app;
    bool will_create_app = false;
    auto decode_err = dsn::try_unmarshall(msg, request);
    if (decode_err != ERR_OK)
    {
        derror("invalid create app request: %s", decode_err.to_string());
        response.err = decode_err;
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
        return;
    }
    
    ddebug("create app request, name(%s), type(%s)", request.app_name.c_str(), request.options.app_type.c_str());

    // partition_count is a client-supplied value; a non-positive value would create
    // a nonsensical app, so reject it here with a clear error (a huge value is guarded
    // separately below when app_state allocates its partition vector).
    if (request.options.partition_count <= 0)
    {
        derror("create app(%s) failed: invalid partition_count %d",
            request.app_name.c_str(), request.options.partition_count);
        response.err = ERR_INVALID_PARAMETERS;
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
        return;
    }

    auto option_match_check = [](const create_app_options& opt, const app_state& exist_app)
    {
        return opt.partition_count==exist_app.partition_count && opt.app_type==exist_app.app_type &&
               opt.envs == exist_app.envs && opt.is_stateful==exist_app.is_stateful &&
               opt.replica_count == exist_app.max_replica_count;
    };

    {
        zauto_write_lock l(_lock);
        app = get_app(request.app_name);
        if (nullptr != app)
        {
            switch (app->status)
            {
            case app_status::AS_AVAILABLE:
                if (!request.options.success_if_exist || !option_match_check(request.options, *app))
                    response.err = ERR_INVALID_PARAMETERS;
                else {
                    response.err = ERR_OK;
                    response.appid = app->app_id;
                }
                break;
            case app_status::AS_CREATING:
                response.err = ERR_BUSY_CREATING;
                break;
            case app_status::AS_DROPPING:
                response.err = ERR_BUSY_DROPPING;
            default:
                break;
            }
        }
        else {
            app_info info;
            info.app_id = next_app_id();
            info.app_name = request.app_name;
            info.app_type = request.options.app_type;
            info.envs = std::move(request.options.envs);
            info.is_stateful = request.options.is_stateful;
            info.max_replica_count = request.options.replica_count;
            info.partition_count = request.options.partition_count;
            info.status = app_status::AS_CREATING;

            try
            {
                // partition_count is an untrusted, client-supplied value; a very
                // large value makes app_state's partitions.assign(partition_count,
                // ...) throw std::bad_alloc/std::length_error. Reject the request
                // with an error instead of aborting the whole meta server.
                app = app_state::create(info);
            }
            catch (const std::exception& ex)
            {
                derror("create app(%s) failed: cannot allocate %d partitions, err: %s",
                    request.app_name.c_str(), request.options.partition_count, ex.what());
                response.err = ERR_INVALID_PARAMETERS;
            }
            if (app != nullptr)
            {
                will_create_app = true;
                _all_apps.emplace(app->app_id, app);
                _exist_apps.emplace(request.app_name, app);
                ++_creating_apps_count;
            }
        }
    }

    if ( will_create_app ) {
        do_app_create(app, msg);
    }
    else {
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
    }
}

void server_state::do_app_drop(std::shared_ptr<app_state>& app, dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_drop_app_response>(
            _meta_svc, msg))
    {
        return;
    }

    blob value = app->encode_json_with_status(app_status::AS_DROPPED);
    std::string app_path = get_app_path(*app);
    auto after_set_app_dropped = [this, app, msg](error_code ec) mutable {
        if (reply_service_not_active_if_stopped<configuration_drop_app_response>(
                _meta_svc, msg))
        {
            return;
        }

        if (ERR_OK == ec || ERR_OBJECT_NOT_FOUND == ec)
        {
            configuration_drop_app_response response;
            {
                zauto_write_lock l(_lock);
                _exist_apps.erase(app->app_name);
                app->status = app_status::AS_DROPPED;
                for (partition_configuration& pc: app->partitions)
                {
                    if (!pc.primary.is_invalid() && _nodes.find(pc.primary)!=_nodes.end()) {
                        _nodes[pc.primary].primaries.erase(pc.pid);
                    }
                    for (dsn::rpc_address& addr: pc.secondaries) {
                        if (_nodes.find(addr) != _nodes.end()) {
                            _nodes[addr].partitions.erase(pc.pid);
                        }
                    }
                }
                for (config_context& cc: app->helpers->contexts)
                    cc.cancel_sync();
                --_dropping_apps_count;
            }
            response.err = ERR_OK;
            reply_message(_meta_svc, msg, response);
            dsn_msg_release_ref(msg);
            dinfo("drop table(id:%d, name:%s) finished", app->app_id, app->app_name.c_str());
        }
        else if (ERR_OBJECT_NOT_FOUND == ec || ERR_INVALID_PARAMETERS == ec || ERR_INCONSISTENT_STATE == ec)
        {
            // Permanent remote-storage errors: retrying the same set-data can
            // never succeed, so fail-stop instead of looping forever.
            dassert(false, "we can't handle this, error(%s)", ec.to_string());
        }
        else
        {
            // Transient remote-storage error -- ERR_TIMEOUT or
            // ERR_ZOOKEEPER_OPERATION (e.g. a marshalling failure under memory
            // pressure): retry the idempotent set-data instead of aborting the
            // whole meta server.
            dwarn("drop table(id:%d, name:%s) failed, err(%s), continue to drop later", app->app_id, app->app_name.c_str(), ec.to_string());
            task_ptr retry_task = enqueue_cancellable_retry(
                &_retry_tasks,
                std::bind(&server_state::do_app_drop, this, app, msg),
                [this, msg] {
                    cancel_pending_request<configuration_drop_app_response>(_meta_svc, msg);
                },
                std::chrono::seconds(1));
            if (retry_task == nullptr)
            {
                derror("enqueue app-drop retry failed, name: %s, retry immediately",
                       app->app_name.c_str());
                do_app_drop(app, msg);
            }
        }
    };
    _meta_svc->get_remote_storage()->set_data(app_path,
        value,
        LPC_META_STATE_HIGH,
        after_set_app_dropped,
        _meta_svc);
}

void server_state::drop_app(dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_drop_app_response>(
            _meta_svc, msg))
    {
        return;
    }

    configuration_drop_app_request request;
    configuration_drop_app_response response;

    bool do_dropping = false;
    std::shared_ptr<app_state> app;
    auto decode_err = dsn::try_unmarshall(msg, request);
    if (decode_err != ERR_OK)
    {
        derror("invalid drop app request: %s", decode_err.to_string());
        response.err = decode_err;
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
        return;
    }
    ddebug("drop app request, name(%s)", request.app_name.c_str());
    {
        zauto_write_lock l(_lock);
        app = get_app(request.app_name);
        if (nullptr == app) {
            response.err = request.options.success_if_not_exist?ERR_OK:ERR_APP_NOT_EXIST;
        }
        else {
            switch (app->status)
            {
            case app_status::AS_AVAILABLE:
                do_dropping = true;
                app->status = app_status::AS_DROPPING;
                ++_dropping_apps_count;
                break;
            case app_status::AS_CREATING:
                response.err = ERR_BUSY_CREATING;
                break;
            case app_status::AS_DROPPING:
                response.err = ERR_BUSY_DROPPING;
                break;
            default:
                dassert(false, "invalid app status");
                break;
            }
        }
    }
    if (do_dropping) {
        do_app_drop(app, msg);
    }
    else {
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
    }
}

void server_state::list_apps(const configuration_list_apps_request& request, configuration_list_apps_response& response)
{
    ddebug("list app request, status(%d)", request.status);
    zauto_read_lock l(_lock);
    for (auto& kv: _all_apps)
    {
        app_state& app = *(kv.second);
        if ( request.status == app_status::AS_INVALID || request.status == app.status)
            response.infos.push_back(app);
    }
    response.err = dsn::ERR_OK;
}

void server_state::send_proposal(rpc_address target, const configuration_update_request &proposal)
{
    ddebug("send proposal %s of %s, gpid(%d.%d), current ballot = %" PRId64,
        enum_to_string(proposal.type),
        proposal.node.to_string(),
        proposal.config.pid.get_app_id(),
        proposal.config.pid.get_partition_index(),
        proposal.config.ballot
        );
    dsn_message_t msg = dsn_msg_create_request(RPC_CONFIG_PROPOSAL, 0, gpid_to_thread_hash(proposal.config.pid));
    ::marshall(msg, proposal);
    _meta_svc->send_message(target, msg);
}

void server_state::send_proposal(const configuration_proposal_action &action, const partition_configuration &pc, const app_state& app)
{
    configuration_update_request request;
    request.info = app;
    request.type = action.type;
    request.node = action.node;
    request.config = pc;
    send_proposal(action.target, request);
}

bool server_state::request_check(const partition_configuration &old, const configuration_update_request& request)
{
    const partition_configuration& new_config = request.config;
    const bool node_is_primary = old.primary == request.node;
    const bool node_is_secondary =
        std::find(old.secondaries.begin(), old.secondaries.end(), request.node) !=
        old.secondaries.end();

    switch (request.type) {
    case config_type::CT_ASSIGN_PRIMARY:
        return !node_is_primary && !node_is_secondary;
    case config_type::CT_UPGRADE_TO_PRIMARY:
        return !node_is_primary && node_is_secondary;
    case config_type::CT_DOWNGRADE_TO_SECONDARY:
        return node_is_primary && !node_is_secondary;
    case config_type::CT_DOWNGRADE_TO_INACTIVE:
    case config_type::CT_REMOVE:
        return node_is_primary || node_is_secondary;
    case config_type::CT_UPGRADE_TO_SECONDARY:
        return !node_is_primary && !node_is_secondary;
    case config_type::CT_PRIMARY_FORCE_UPDATE_BALLOT:
        return old.primary == new_config.primary && old.secondaries == new_config.secondaries;
    case config_type::CT_ADD_SECONDARY:
    case config_type::CT_ADD_SECONDARY_FOR_LB:
        return false;
    default:
        return false;
    }
}

void server_state::update_configuration_locally(app_state& app, std::shared_ptr<configuration_update_request>& config_request)
{
    dsn::gpid& gpid = config_request->config.pid;
    partition_configuration& old_cfg = app.partitions[gpid.get_partition_index()];
    partition_configuration& new_cfg = config_request->config;

    dassert(old_cfg.ballot + 1 == new_cfg.ballot,
        "invalid configuration update request, old ballot %" PRId64 ", new ballot %" PRId64 "",
        old_cfg.ballot, new_cfg.ballot);

    if (app.is_stateful)
    {
        auto iter = _nodes.find(config_request->node);
        dassert(iter != _nodes.end(), "");
        node_state& ns = iter->second;

        switch (config_request->type) {
        case config_type::CT_ASSIGN_PRIMARY:
        case config_type::CT_UPGRADE_TO_PRIMARY:
            ns.partitions.insert(gpid);
            ns.primaries.insert(gpid);
            break;

        case config_type::CT_UPGRADE_TO_SECONDARY:
            ns.partitions.insert(gpid);
            break;

        case config_type::CT_DOWNGRADE_TO_SECONDARY:
            ns.primaries.erase(gpid);
            break;

        case config_type::CT_DOWNGRADE_TO_INACTIVE:
        case config_type::CT_REMOVE:
            ns.primaries.erase(gpid);
            ns.partitions.erase(gpid);
            break;
        //nothing to handle, the ballot will updated in below
        case config_type::CT_PRIMARY_FORCE_UPDATE_BALLOT:
            break;

        case config_type::CT_ADD_SECONDARY:
        case config_type::CT_ADD_SECONDARY_FOR_LB:
            dassert(false, "invalid execution work flow");
            break;
        default:
            dassert(false, "");
            break;
        }
    }
    else
    {
        auto it = _nodes.find(config_request->host_node);
        dassert(it != _nodes.end(), "");
        if (config_type::CT_REMOVE == config_request->type)
        {
            it->second.partitions.erase(gpid);
        }
        else
        {
            it->second.partitions.insert(gpid);
        }
    }

    //we assume config in config_request stores the proper new config
    //as we sync to remote storage according to it
    old_cfg = config_request->config;
    std::stringstream cf;
    cf << *config_request;
    ddebug("meta update config ok: %s", cf.str().c_str());

#ifndef NDEBUG
    check_consistency(gpid);
#endif
    if (_config_change_subscriber)
    {
        _config_change_subscriber(_all_apps);
    }
}

task_ptr server_state::update_configuration_on_remote(std::shared_ptr<configuration_update_request>& config_request)
{
    partition_configuration& pc = config_request->config;
    std::string storage_path = get_partition_path(pc.pid);

    blob json_config = dsn::json::json_forwarder<partition_configuration>::encode(pc);
    return _meta_svc->get_remote_storage()->set_data(
        storage_path,
        json_config,
        LPC_META_STATE_HIGH,
        std::bind(&server_state::on_update_configuration_on_remote_reply,
            this,
            std::placeholders::_1,
            config_request),
        _meta_svc
    );
}

void server_state::abort_configuration_sync(config_context& context,
                                             const partition_configuration& config)
{
    context.pending_sync_task = nullptr;
    context.pending_sync_request.reset();
    context.stage = config_status::not_pending;
    if (context.msg)
    {
        configuration_update_response response;
        response.err = ERR_SERVICE_NOT_ACTIVE;
        response.config = config;
        reply_message(_meta_svc, context.msg, response);
        dsn_msg_release_ref(context.msg);
        context.msg = nullptr;
    }
}

void server_state::schedule_configuration_retry(
    std::shared_ptr<configuration_update_request>& config_request, config_context& context)
{
    context.pending_sync_task = enqueue_cancellable_retry(
        &_retry_tasks,
        [this, config_request, &context]() mutable {
            zauto_write_lock l(_lock);
            if (_meta_svc->is_stopped())
            {
                abort_configuration_sync(context, config_request->config);
                return;
            }
            context.pending_sync_task = update_configuration_on_remote(config_request);
        },
        [] {},
        std::chrono::seconds(1));

    if (context.pending_sync_task == nullptr)
    {
        derror("enqueue configuration retry failed, gpid(%d.%d), retry immediately",
               config_request->config.pid.get_app_id(),
               config_request->config.pid.get_partition_index());
        context.pending_sync_task = update_configuration_on_remote(config_request);
    }
}

void server_state::on_update_configuration_on_remote_reply(error_code ec, std::shared_ptr<configuration_update_request>& config_request)
{
    zauto_write_lock l(_lock);
    dsn::gpid& gpid = config_request->config.pid;
    std::shared_ptr<app_state> app = get_app(gpid.get_app_id());
    config_context& cc = app->helpers->contexts[gpid.get_partition_index()];
    if (_meta_svc->is_stopped())
    {
        abort_configuration_sync(cc, config_request->config);
        return;
    }

    //if multiple threads exist in the thread pool, the check may be failed
    dassert(app->status==app_status::AS_AVAILABLE || app->status==app_status::AS_DROPPING, "if app removed, this task should be cancelled");
    if (ec == ERR_TIMEOUT)
    {
        schedule_configuration_retry(config_request, cc);
    }
    else if (ec == ERR_OK)
    {
        update_configuration_locally(*app, config_request);
        cc.pending_sync_task = nullptr;
        cc.pending_sync_request.reset();
        cc.stage = config_status::not_pending;
        if (cc.msg)
        {
            configuration_update_response resp;
            resp.err = ERR_OK;
            resp.config = config_request->config;
            reply_message(_meta_svc, cc.msg, resp);
            dsn_msg_release_ref(cc.msg);
            cc.msg = nullptr;
        }

        _meta_svc->get_balancer()->reconfig({&_all_apps, &_nodes}, *config_request);
        configuration_proposal_action action;
        _meta_svc->get_balancer()->cure({&_all_apps, &_nodes}, gpid, action);
        if (action.type != config_type::CT_INVALID)
        {
            config_request->type = action.type;
            config_request->node = action.node;
            config_request->info = *app;
            send_proposal(action.target, *config_request);
        }
    }
    else if (ERR_OBJECT_NOT_FOUND == ec || ERR_INVALID_PARAMETERS == ec || ERR_INCONSISTENT_STATE == ec)
    {
        // Permanent remote-storage errors: retrying the same set_data can never
        // succeed (e.g. the partition znode is missing or the request is
        // malformed), so fail-stop instead of leaving the partition pending
        // forever.
        dassert(false, "we can't handle this right now, err = %s", ec.to_string());
    }
    else
    {
        // Transient remote-storage error such as ERR_ZOOKEEPER_OPERATION (e.g. a
        // marshalling failure under memory pressure): retry the idempotent
        // set_data, the same way ERR_TIMEOUT is handled above.
        dwarn("update configuration on remote storage failed, gpid(%d.%d), err(%s), retry later",
              gpid.get_app_id(), gpid.get_partition_index(), ec.to_string());
        schedule_configuration_retry(config_request, cc);
    }
}

void server_state::downgrade_primary_to_inactive(std::shared_ptr<app_state>& app, int pidx)
{
    partition_configuration& pc = app->partitions[pidx];
    config_context& cc = app->helpers->contexts[pidx];

    std::shared_ptr<configuration_update_request> req = std::make_shared<configuration_update_request>();
    configuration_update_request& request = *req;
    request.info = *app;
    request.config = pc;
    request.type = config_type::CT_DOWNGRADE_TO_INACTIVE;
    request.node = pc.primary;
    request.config.ballot++;
    request.config.primary.set_invalid();
    maintain_drops(request.config.last_drops, pc.primary, false);

    if (config_status::pending_remote_sync == cc.stage)
    {
        dwarn("gpid(%d.%d) is syncing another request with remote, cancel it due to the primary(%s) is down",
            pc.pid.get_app_id(), pc.pid.get_partition_index(), pc.primary.to_string());
        cc.cancel_sync();
    }
    cc.stage = config_status::pending_remote_sync;
    cc.pending_sync_request = req;
    cc.msg = nullptr;

    cc.pending_sync_task = update_configuration_on_remote(req);
}

void server_state::downgrade_secondary_to_inactive(std::shared_ptr<app_state>& app, int pidx, const rpc_address &node)
{
    partition_configuration& pc = app->partitions[pidx];
    config_context& cc = app->helpers->contexts[pidx];

    dassert(!pc.primary.is_invalid(), "this shouldn't be called if the primary is invalid");
    if (config_status::pending_remote_sync != cc.stage)
    {
        configuration_update_request request;
        request.info = *app;
        request.config = pc;
        request.type = config_type::CT_DOWNGRADE_TO_INACTIVE;
        request.node = node;
        send_proposal(pc.primary, request);
    }
    else
    {
        ddebug("gpid(%d.%d) is syncing with remote storage, ignore the remove seconary(%s)",
            app->app_id, pidx, node.to_string());
    }
}

void server_state::downgrade_stateless_nodes(std::shared_ptr<app_state>& app, int pidx, const rpc_address& address)
{
    std::shared_ptr<configuration_update_request> req = std::make_shared<configuration_update_request>();
    req->info = *app;
    req->type = config_type::CT_REMOVE;
    req->host_node = address;
    req->node.set_invalid();
    req->config = app->partitions[pidx];

    config_context& cc = app->helpers->contexts[pidx];
    partition_configuration& pc = req->config;

    unsigned i=0;
    for (; i<pc.secondaries.size(); ++i)
    {
        if (pc.secondaries[i] == address)
        {
            req->node = pc.last_drops[i];
            break;
        }
    }
    dassert(!req->node.is_invalid(), "");
    //remove host_node & node from secondaries/last_drops, as it will be sync to remote storage
    for (++i; i<pc.secondaries.size(); ++i)
    {
        pc.secondaries[i-1] = pc.secondaries[i];
        pc.last_drops[i-1] = pc.last_drops[i];
    }
    pc.secondaries.pop_back();
    pc.last_drops.pop_back();

    if (config_status::pending_remote_sync == cc.stage)
    {
        dwarn("gpid(%d.%d) is syncing another request with remote, cancel it due to meta is removing host(%s) worker(%s)",
            pc.pid.get_app_id(), pc.pid.get_partition_index(), req->host_node.to_string(), req->node.to_string());
        cc.cancel_sync();
    }
    cc.stage = config_status::pending_remote_sync;
    cc.pending_sync_request = req;
    cc.msg = nullptr;

    cc.pending_sync_task = update_configuration_on_remote(req);
}

void server_state::on_update_configuration(std::shared_ptr<configuration_update_request>& cfg_request, dsn_message_t msg)
{
    if (reply_service_not_active_if_stopped<configuration_update_response>(
            _meta_svc, msg))
    {
        return;
    }

    zauto_write_lock l(_lock);
    dsn::gpid& gpid = cfg_request->config.pid;
    std::shared_ptr<app_state> app = get_app(gpid.get_app_id());
    configuration_update_response response;
    response.err = ERR_IO_PENDING;

    //table is removed, or the request references an invalid partition (e.g. corrupted request)
    if (app == nullptr || app->status!=app_status::AS_AVAILABLE
        || gpid.get_partition_index() < 0
        || gpid.get_partition_index() >= app->partition_count)
    {
        response.err = ERR_INVALID_VERSION;
        response.config.ballot = cfg_request->config.ballot+1;
        response.config.pid = gpid;
        response.config.primary.set_invalid();
        response.config.secondaries.clear();
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
        return;
    }

    partition_configuration& pc = app->partitions[gpid.get_partition_index()];
    config_context& cc = app->helpers->contexts[gpid.get_partition_index()];

    if (app->is_stateful && !is_valid_stateful_partition_config(*cfg_request))
    {
        derror("invalid update configuration request for gpid(%d.%d): member node is in last_drops",
               gpid.get_app_id(),
               gpid.get_partition_index());
        response.err = ERR_INVALID_DATA;
        response.config = pc;
    }
    else if (app->is_stateful && _nodes.find(cfg_request->node) == _nodes.end())
    {
        derror("invalid update configuration request for gpid(%d.%d): node(%s) is not a known replica node",
               gpid.get_app_id(),
               gpid.get_partition_index(),
               cfg_request->node.to_string());
        response.err = ERR_INVALID_DATA;
        response.config = pc;
    }
    else if (!app->is_stateful && _nodes.find(cfg_request->host_node) == _nodes.end())
    {
        derror("invalid update configuration request for gpid(%d.%d): host_node(%s) is not a known node",
               gpid.get_app_id(),
               gpid.get_partition_index(),
               cfg_request->host_node.to_string());
        response.err = ERR_INVALID_DATA;
        response.config = pc;
    }
    else if (app->is_stateful && is_partition_config_equal(pc, cfg_request->config))
    {
        ddebug("duplicated update request for gpid(%d.%d), ballot: %" PRId64 "", gpid.get_app_id(), gpid.get_partition_index(), pc.ballot);
        response.err = ERR_OK;
        response.config = cfg_request->config;
    }
    else if (config_status::pending_remote_sync == cc.stage)
    {
        std::stringstream ss;
        ss << *cfg_request;
        ddebug("another request is syncing with remote storage, ignore current request(%s)", ss.str().c_str());
        // we don't reply the replica server, expect it to retry
        dsn_msg_release_ref(msg);
        // ERR_IO_PENDING is used as a local sentinel here; no response will be sent on this path.
        response.err.end_tracking();
        return;
    }
    else if (pc.ballot + 1 != cfg_request->config.ballot)
    {
        ddebug("update configuration for gpid(%d.%d) reject coz ballot not match, request ballot: %" PRId64 ", meta ballot: %" PRId64 "",
            gpid.get_app_id(), gpid.get_partition_index(), cfg_request->config.ballot, pc.ballot);
        response.err = ERR_INVALID_VERSION;
        response.config = pc;
    }
    else if (app->is_stateful && !request_check(pc, *cfg_request))
    {
        derror("invalid update configuration request for gpid(%d.%d): type = %s, node = %s",
               gpid.get_app_id(),
               gpid.get_partition_index(),
               enum_to_string(cfg_request->type),
               cfg_request->node.to_string());
        response.err = ERR_INVALID_DATA;
        response.config = pc;
    }
    else // ok
    {
        if (app->is_stateful)
        {
            switch (cfg_request->type)
            {
            case config_type::CT_UPGRADE_TO_PRIMARY:
            case config_type::CT_ASSIGN_PRIMARY:
            case config_type::CT_UPGRADE_TO_SECONDARY:
                maintain_drops(cfg_request->config.last_drops, cfg_request->node, true);
                break;
            case config_type::CT_DOWNGRADE_TO_INACTIVE:
            case config_type::CT_REMOVE:
                maintain_drops(cfg_request->config.last_drops, cfg_request->node, false);
                break;
            default:
                break;
            }
        }
        else
        {
            // nothing to do, the daemon should already maintain ok for the config in requests
        }
    }

    if (response.err != ERR_IO_PENDING)
    {
        reply_message(_meta_svc, msg, response);
        dsn_msg_release_ref(msg);
    }
    else
    {
        dassert(config_status::not_pending==cc.stage || config_status::pending_proposal==cc.stage, "");
        cc.stage = config_status::pending_remote_sync;
        cc.pending_sync_request = cfg_request;
        cc.msg = msg;
        cc.pending_sync_task = update_configuration_on_remote(cfg_request);
    }
}

void server_state::on_partition_node_dead(std::shared_ptr<app_state>& app, int pidx, const dsn::rpc_address& address)
{
    partition_configuration& pc = app->partitions[pidx];
    if (app->is_stateful)
    {
        if (is_primary(pc, address))
            downgrade_primary_to_inactive(app, pidx);
        else if (is_secondary(pc, address))
        {
            if (!pc.primary.is_invalid())
                downgrade_secondary_to_inactive(app, pidx, address);
            else if(is_secondary(pc, address))
            {
                dwarn("gpid(%d.%d) secondary(%s) is down, ignored it due to no primary for this partition available",
                    pc.pid.get_app_id(), pc.pid.get_partition_index(), address.to_string());
            }
            else
            {
                dassert(false, "");
            }
        }
    }
    else
    {
        downgrade_stateless_nodes(app, pidx, address);
    }
}

void server_state::on_change_node_state(rpc_address node, bool is_alive)
{
    if (_meta_svc->is_stopped())
    {
        return;
    }

    dinfo("change node(%s) state to %s", node.to_string(), is_alive?"alive":"dead");
    zauto_write_lock l(_lock);
    if (!is_alive)
    {
        auto iter = _nodes.find(node);
        if (iter == _nodes.end())
        {
            dwarn("node(%s) doesn't exist in the node state, just ignore", node.to_string());
        }
        else
        {
            node_state& ns = iter->second;
            ns.is_alive = false;
            for (auto& gpid: ns.partitions)
            {
                std::shared_ptr<app_state> app = get_app(gpid.get_app_id());
                dassert(app != nullptr && app->status!=app_status::AS_DROPPED, "");
                on_partition_node_dead(app, gpid.get_partition_index(), node);
            }
        }
    }
    else
    {
        _nodes[node].address = node;
        _nodes[node].is_alive = true;
    }
}

void server_state::on_propose_balancer(const configuration_balancer_request& request, configuration_balancer_response& response)
{
    zauto_write_lock l(_lock);
    std::shared_ptr<app_state> app = get_app(request.gpid.get_app_id());
    if (app==nullptr || app->status!=app_status::AS_AVAILABLE || request.gpid.get_partition_index()<0 || request.gpid.get_partition_index()>=app->partition_count)
        response.err = ERR_INVALID_PARAMETERS;
    else
    {
        partition_configuration& pc = app->partitions[request.gpid.get_partition_index()];
        config_context& cc = app->helpers->contexts[request.gpid.get_partition_index()];
        if (cc.balancer_proposal != nullptr)
        {
            ddebug("an exist balancer proposal is executing, ignore current one");
            response.err = ERR_INVALID_PARAMETERS;
        }
        else if (request.force)
        {
            for (const configuration_proposal_action& act: request.action_list)
                send_proposal(act, pc, *app);
        }
        else
        {
            cc.balancer_proposal = std::make_shared<configuration_balancer_request>(request);
            for (configuration_proposal_action& act: cc.balancer_proposal->action_list)
                if (act.target.is_invalid())
                    act.target = pc.primary;
        }
        response.err = ERR_OK;
    }
}

void server_state::clear_proposals()
{
    if (_meta_svc->is_stopped())
    {
        return;
    }

    ddebug("clear all exist proposals");
    zauto_write_lock l(_lock);
    for (auto& kv: _exist_apps)
    {
        std::shared_ptr<app_state>& app = kv.second;
        app->helpers->clear_proposals();
    }
}

void server_state::apply_migration_actions(migration_list &ml)
{
    for (std::shared_ptr<configuration_balancer_request>& req: ml)
    {
        dsn::gpid& gpid = req->gpid;
        std::shared_ptr<app_state> app = get_app(gpid.get_app_id());
        dassert(app->status==app_status::AS_AVAILABLE, "");
        config_context& cc = app->helpers->contexts[gpid.get_partition_index()];
        cc.balancer_proposal = std::move(req);
    }
    ml.clear();
}

bool server_state::is_server_state_stable(int healthy_partitions)
{
    //dead nodes check
    for (auto iter=_nodes.begin(); iter!=_nodes.end();) {
        if (!iter->second.is_alive) {
            if (!iter->second.partitions.empty()) {
                ddebug("don't do replica migration coz dead node(%s) has %zu partitions not removed",
                       iter->second.address.to_string(), iter->second.partitions.size());
                return false;
            }
            _nodes.erase(iter++);
        }
        else
            ++iter;
    }

    //partition health check
    int total_count = count_partitions(_all_apps);
    if (healthy_partitions != total_count) {
        ddebug("don't do replica migration coz not all partitions are healthy, "
               "total_partitions(%d) vs normal partitions(%d), ",
               total_count, healthy_partitions);
        return false;
    }

    //table stability check
    int creating_cnt = _creating_apps_count.load();
    int dropping_cnt = _dropping_apps_count.load();
    if (creating_cnt!=0 || dropping_cnt!=0) {
        ddebug("don't do replica migration coz there are transient app status: creating(%d), dropping(%d)", creating_cnt, dropping_cnt);
        return false;
    }

    return true;
}

bool server_state::check_all_partitions()
{
    int healthy_partitions = 0;
    bool is_service_freeze = _meta_svc->is_service_freezed();
    bool is_migration_disabled = (_meta_svc->get_control_flags()&meta_ctrl_flags::ctrl_disable_replica_migration);

    zauto_write_lock l(_lock);
    for (auto& app_pair: _exist_apps)
    {
        std::shared_ptr<app_state>& app = app_pair.second;
        if (app->status == app_status::AS_CREATING || app->status == app_status::AS_DROPPING)
            continue;
        for (unsigned int i=0; i!=app->partition_count; ++i)
        {
            partition_configuration& pc = app->partitions[i];
            config_context& cc = app->helpers->contexts[i];

            if (cc.stage != config_status::pending_remote_sync && !is_service_freeze)
            {
                configuration_proposal_action action;
                pc_status s = _meta_svc->get_balancer()->cure({&_all_apps, &_nodes}, pc.pid, action);
                dinfo("gpid(%d.%d) is in status(%s)", pc.pid.get_app_id(), pc.pid.get_partition_index(), enum_to_string(s));
                if (pc_status::healthy == s)
                {
                    ++healthy_partitions;
                }
                else if (action.type != config_type::CT_INVALID)
                {
                    send_proposal(action, pc, *app);
                }
            }
        }
    }

    if (is_service_freeze || is_migration_disabled)
    {
        ddebug("don't do replica migration coz meta server forbidden this: %s", is_service_freeze?"freezed":"migration_disabled");
        return false;
    }

    if ( !is_server_state_stable(healthy_partitions) )
        return false;

    dinfo("try to do replica migration");
    if (_meta_svc->get_balancer()->balance({&_all_apps, &_nodes}, _temporary_list) )
    {
        if (_replica_migration_subscriber)
            _replica_migration_subscriber(_temporary_list);

        apply_migration_actions(_temporary_list);
        tasking::enqueue(LPC_META_STATE_NORMAL, _meta_svc, std::bind(&meta_service::balancer_run, _meta_svc));
        return false;
    }
    return true;
}

void server_state::check_consistency(const dsn::gpid& gpid)
{
    auto iter = _all_apps.find(gpid.get_app_id());
    dassert(iter!=_all_apps.end(), "");

    app_state& app = *(iter->second);
    partition_configuration& config = app.partitions[gpid.get_partition_index()];

    if (app.is_stateful)
    {
        if (config.primary.is_invalid() == false)
        {
            auto it = _nodes.find(config.primary);
            dassert(it != _nodes.end(), "");
            dassert(it->second.primaries.find(gpid) != it->second.primaries.end(), "");
            dassert(it->second.partitions.find(gpid) != it->second.partitions.end(), "");

            auto it2 = std::find(config.last_drops.begin(), config.last_drops.end(), config.primary);
            dassert(it2 == config.last_drops.end(), "");
        }
    
        for (auto& ep : config.secondaries)
        {
            auto it = _nodes.find(ep);
            dassert(it != _nodes.end(), "");
            dassert(it->second.partitions.find(gpid) != it->second.partitions.end(), "");

            auto it2 = std::find(config.last_drops.begin(), config.last_drops.end(), ep);
            dassert(it2 == config.last_drops.end(), "");
        }
    }
    else
    {
        partition_configuration_stateless pcs(config);
        dassert(pcs.hosts().size() == pcs.workers().size(), "");
        for (auto& ep : pcs.hosts())
        {
            auto it = _nodes.find(ep);
            dassert(it != _nodes.end(), "");
            dassert(it->second.partitions.find(gpid) != it->second.partitions.end(), "");
        }
    }
}

void server_state::json_state(std::stringstream& out) const
{
    zauto_read_lock _(_lock);
    JSON_ENCODE_ENTRIES(out, *this, _nodes, _exist_apps);
}

void server_state::static_cli_json_state(void* context, int argc, const char** argv, dsn_cli_reply* reply)
{
    auto _server_state = reinterpret_cast<server_state*>(context);
    std::stringstream out;
    _server_state->json_state(out);
    auto danglingstring = new std::string(out.str());
    reply->message = danglingstring->c_str();
    reply->size = danglingstring->size();
    reply->context = danglingstring;
}

void server_state::static_cli_json_state_cleanup(dsn_cli_reply reply)
{
    dassert(reply.context != nullptr, "corrupted cli reply context");
    auto danglingstring = reinterpret_cast<std::string*>(reply.context);
    dassert(reply.message == danglingstring->c_str(), "corrupted cli reply message");
    delete danglingstring;
}

void server_state::static_cli_dump_app_states(void *context, int argc, const char **argv, dsn_cli_reply *reply)
{
    server_state* _this = reinterpret_cast<server_state*>(context);
    std::string* dump_result;
    if (argc != 4)
    {
        dump_result = new std::string("invalid command parameter");
    }
    else
    {
        const char* target_file = nullptr;
        for (int i=0; i<argc; i+=2)
        {
            if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0)
                target_file = argv[i+1];
        }

        if (target_file==nullptr)
        {
            dump_result = new std::string("invalid command parameter");
        }
        else
        {
            error_code ec = _this->dump_from_remote_storage(target_file, false);
            dump_result = new std::string("execute result: ");
            dump_result->append(ec.to_string());
        }
    }

    reply->message = dump_result->c_str();
    reply->size = dump_result->size();
    reply->context = dump_result;
}

void server_state::static_cli_dump_app_states_cleanup(dsn_cli_reply reply)
{
    dassert(reply.context != nullptr, "corrupted cli context");
    std::string* dump_result = reinterpret_cast<std::string*>(reply.context);
    delete dump_result;
}

}}
