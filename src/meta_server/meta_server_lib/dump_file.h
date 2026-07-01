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
 *     A simple dump file implementation for meta server, which can be used to dump meta's server-state
 *
 * Revision history:
 *     2015-12-10, Weijie Sun(sunweijie at xiaomi.com), first version
 *     xxxx-xx-xx, author, fix bug about xxx
 */
#ifndef DUMP_FILE_H
#define DUMP_FILE_H

#include <dsn/service_api_c.h>
#include <dsn/service_api_cpp.h>
#include <cstdio>
#include <cerrno>
#include <iostream>
#include <exception>

inline void error_msg(int err_number, /*out*/char* buffer, int buflen)
{
#ifdef _WIN32
    int result = strerror_s(buffer, buflen, err_number);
    if (result != 0)
        fprintf(stderr, "maybe unknown err number(%d)", err_number);
#else
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    char* result = strerror_r(err_number, buffer, buflen);
    if (result != buffer) {
        fprintf(stderr, "%s\n", result);
    }
#else
    int result = strerror_r(err_number, buffer, buflen);
    if (result != 0)
        fprintf(stderr, "maybe unknown err number(%d)", err_number);
#endif
#endif
}

#define log_error_and_return(buffer, length) do {\
    error_msg(errno, buffer, length);\
    derror("append file failed, reason(%s)", buffer);\
    return -1;\
} while (0)

struct block_header{
    uint32_t length;
    uint32_t crc32;
};

class dump_file {
public:
    ~dump_file()
    {
        if (_file_handle != nullptr)
        {
            // In write mode fclose flushes any buffered data, so a disk error
            // (e.g. ENOSPC) can surface here. There is no way to propagate it
            // out of a destructor, so at least make it visible instead of
            // silently losing the tail of the dump. Callers that need to know
            // the dump succeeded must call flush() and check its result before
            // destroying this object.
            if (fclose(_file_handle) != 0 && _is_write)
                derror("close dump file %s failed, the dump may be incomplete", _filename.c_str());
        }
    }

    static std::shared_ptr<dump_file> open_file(const char* filename, bool is_write)
    {
        std::shared_ptr<dump_file> res(new dump_file());
        res->_filename = filename;
        if ( is_write )
            res->_file_handle = fopen(filename, "wb");
        else
            res->_file_handle = fopen(filename, "rb");
        res->_is_write = is_write;

        if ( res->_file_handle == nullptr)
            return nullptr;
        return res;
    }

    int append_buffer(const char* data, uint32_t data_length)
    {
        static __thread char msg_buffer[128];

        dassert(_is_write, "call append when open file with read mode");

        block_header hdr = {data_length, 0};
        hdr.crc32 = dsn_crc32_compute(data, data_length, _crc);
        _crc = hdr.crc32;
        size_t len = fwrite(&hdr, sizeof(hdr), 1, _file_handle);
        if (len < 1)
        {
            log_error_and_return(msg_buffer, 128);
        }

        len = 0;
        while (len < data_length)
        {
            size_t cnt = fwrite(data+len, 1, data_length-len, _file_handle);
            if (len+cnt<data_length && errno!=EINTR)
            {
                log_error_and_return(msg_buffer, 128);
            }
            len += cnt;
        }
        return 0;
    }
    int append_buffer(const dsn::blob& data)
    {
        return append_buffer(data.data(), data.length());
    }
    int append_buffer(const std::string& data)
    {
        return append_buffer(data.c_str(), data.size());
    }
    // Force any buffered data out to the OS and report a write failure that
    // would otherwise only surface (and be swallowed) at fclose time. Returns
    // 0 on success and -1 on error. Callers must invoke this after the last
    // append_buffer and check the result before treating the dump as complete.
    int flush()
    {
        static __thread char msg_buffer[128];

        dassert(_is_write, "call flush when open file with read mode");

        if (_file_handle != nullptr && fflush(_file_handle) != 0)
        {
            log_error_and_return(msg_buffer, 128);
        }
        return 0;
    }
    int read_next_buffer(/*out*/dsn::blob& output)
    {
        static __thread char msg_buffer[128];
        dassert(!_is_write, "call read next buffer when open file with write mode");

        block_header hdr;
        size_t len = fread(&hdr, sizeof(hdr), 1, _file_handle);
        if (len < 1 )
        {
            if ( feof(_file_handle) )
                return 0;
            else {
                log_error_and_return(msg_buffer, 128);
            }
        }

        // hdr.length comes straight from the on-disk block header and is not yet
        // validated (the crc32 check below runs only after the payload is read).
        // A corrupt/huge length would make make_shared_array throw bad_alloc and
        // abort the process, so allocate defensively and treat failure as a
        // corrupt block instead of letting it escape.
        std::shared_ptr<char> ptr;
        try
        {
            ptr = dsn::make_shared_array<char>(hdr.length);
        }
        catch (const std::exception& e)
        {
            derror("file %s: failed to allocate %u bytes for the next block "
                   "(corrupt block length?), err(%s)",
                   _filename.c_str(), hdr.length, e.what());
            return -1;
        }
        char* raw_mem = ptr.get();
        len = 0;
        while (len < hdr.length)
        {
            size_t cnt = fread(raw_mem+len, 1, hdr.length-len, _file_handle);
            if (len+cnt<hdr.length)
            {
                if ( feof(_file_handle) )
                {
                    derror("unexpected file end, start offset of this block (%ld)", (long)(ftell(_file_handle)-len-sizeof(hdr)));
                    return -1;
                }
                else if (errno != EINTR)
                {
                    log_error_and_return(msg_buffer, 128);
                }
            }
            len += cnt;
        }
        _crc = dsn_crc32_compute(raw_mem, len, _crc);
        if (_crc != hdr.crc32)
        {
            derror("file %s data error, block offset(%ld)", _filename.c_str(), ftell(_file_handle)-hdr.length-sizeof(hdr));
            return -1;
        }

        output.assign(ptr, 0, hdr.length);
        return 1;
    }

private:
    dump_file(): _file_handle(nullptr), _crc(0) {}
    bool _is_write;//true for write, false for read
    FILE* _file_handle;
    std::string _filename;
    uint32_t _crc;
};
#endif // DUMP_FILE_H
