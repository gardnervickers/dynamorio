/* **********************************************************
 * Copyright (c) 2023 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* lz4_ostream_t: a wrapper around lz4 to match the parts of the
 * std::ostream interface we use for raw2trace and file_reader_t.
 */

#ifndef _LZ4_OSTREAM_H_
#define _LZ4_OSTREAM_H_ 1

#ifndef HAS_LZ4
#    error HAS_LZ4 is required
#endif

#include <array>
#include <fstream>
#include <streambuf>
#include <vector>
#include <lz4frame.h>

namespace dynamorio {
namespace drmemtrace {

class lz4_ostreambuf_t : public std::basic_streambuf<char, std::char_traits<char>> {
public:
    lz4_ostreambuf_t(const std::string &path)
    {
        auto res = LZ4F_createCompressionContext(&lzctx_, LZ4F_VERSION);
        if (LZ4F_isError(res)) {
            lzctx_ = nullptr;
            failed_ = true;
            return;
        }

        // LZ4 writes compressed output into dest_buf_, so it needs real elements,
        // not just reserved capacity.  front() on an empty vector is undefined and
        // aborts under _GLIBCXX_ASSERTIONS, which gcc 15+ enables at -O0.
        dest_buf_.resize(LZ4F_compressBound(src_buf_.size(), nullptr));
        file_ = new std::ofstream(path);
        if (!*file_) {
            failed_ = true;
            return;
        }

        char *base = src_buf_.data();
        setp(base, base + src_buf_.size() - 1);

        write_header();
    }

    ~lz4_ostreambuf_t()
    {
        if (!failed_) {
            sync();
            write_footer();
        }
        if (file_ != nullptr) {
            delete file_;
            file_ = nullptr;
        }
        if (lzctx_ != nullptr)
            LZ4F_freeCompressionContext(lzctx_);
    }

private:
    int
    overflow(int extra_char) override
    {
        if (failed_)
            return traits_type::eof();

        if (extra_char != traits_type::eof()) {
            *pptr() = traits_type::to_char_type(extra_char);
            pbump(1);
        }
        if (!compress_pending())
            return traits_type::eof();
        return traits_type::not_eof(extra_char);
    }

    // Compresses and writes out the data in our buffer, and then flushes both what
    // LZ4 holds back and the file.
    int
    sync() override
    {
        if (failed_ || !compress_pending())
            return -1;
        auto res = LZ4F_flush(lzctx_, dest_buf_.data(), dest_buf_.size(), nullptr);
        if (LZ4F_isError(res)) {
            fail();
            return -1;
        }
        if (!write_out(res))
            return -1;
        if (!file_->flush()) {
            fail();
            return -1;
        }
        return 0;
    }

    // Hands the data in our buffer to LZ4 and writes what it produces.  The data is
    // consumed either way: on an error we accept nothing more rather than
    // compress it again.
    bool
    compress_pending()
    {
        int size = static_cast<int>(pptr() - pbase());
        pbump(-size);
        if (size == 0)
            return true;
        auto res = LZ4F_compressUpdate(lzctx_, dest_buf_.data(), dest_buf_.size(),
                                       pbase(), size, nullptr);
        if (LZ4F_isError(res)) {
            fail();
            return false;
        }
        return write_out(res);
    }

    bool
    write_out(size_t size)
    {
        if (size > 0 && !file_->write(dest_buf_.data(), size)) {
            fail();
            return false;
        }
        return true;
    }

    // Stops accepting data: the stream using us then fails its writes.
    void
    fail()
    {
        failed_ = true;
        setp(nullptr, nullptr);
    }

    void
    write_header()
    {
        auto res =
            LZ4F_compressBegin(lzctx_, dest_buf_.data(), dest_buf_.size(), nullptr);
        if (LZ4F_isError(res)) {
            fail();
            return;
        }
        write_out(res);
    }

    void
    write_footer()
    {
        auto res = LZ4F_compressEnd(lzctx_, dest_buf_.data(), dest_buf_.size(), nullptr);
        if (LZ4F_isError(res)) {
            fail();
            return;
        }
        if (write_out(res))
            file_->flush();
    }

private:
    static const int buffer_size_ = 1024 * 1024;
    std::ostream *file_ = nullptr;
    std::array<char, buffer_size_> src_buf_;
    std::vector<char> dest_buf_;
    LZ4F_compressionContext_t lzctx_ = nullptr;
    bool failed_ = false;
};

class lz4_ostream_t : public std::ostream {
public:
    explicit lz4_ostream_t(const std::string &path)
        : std::ostream(new lz4_ostreambuf_t(path))
    {
        if (!rdbuf())
            setstate(std::ios::badbit);
    }

    ~lz4_ostream_t() override
    {
        delete rdbuf();
    }
};

} // namespace drmemtrace
} // namespace dynamorio

#endif // _LZ4_OSTREAM_H_
