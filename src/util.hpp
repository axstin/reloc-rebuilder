#pragma once

#include <cstdint>
#include <stdexcept>

#define ALIGN_UP(x, y) (((x) + ((y) - 1)) & -(int)(y))
#define ALIGN_DOWN(x, y) ((x) & -(int)(y))

namespace util
{
    template <typename T>
    class array_view
    {
        T *pointer = nullptr;
        size_t num_items = 0;

    public:
        array_view() {}
        array_view(T *pointer, size_t num_items) : pointer(pointer), num_items(pointer ? num_items : 0) {}

        T *data() const { return pointer; }
        size_t size() const { return num_items; }
        T *begin() const { return data(); }
        T *end() const { return data() + size(); }
        bool empty() const { return size() == 0; }
        bool valid() const { return pointer != nullptr; }
        void reset() { pointer = nullptr; num_items = 0; }

        explicit operator bool() const { return valid(); }
        T &operator[](size_t index) { return pointer[index]; }
        const T &operator[](size_t index) const { return pointer[index]; }

        T &at(size_t index)
        {
            if (index >= num_items) throw std::out_of_range("invalid array_view subscript");
            return pointer[index];
        }

        const T &at(size_t index) const { return const_cast<array_view *>(this)->at(index); }
    };

    class memory_region
    {
        uint8_t *buffer = nullptr;
        size_t length = 0;

    public:
        memory_region() {};
        memory_region(void *buffer, size_t length) { reset(buffer, length); }

        bool valid() const { return length != 0; }
        size_t size() const { return length; }
        uint8_t *data() const { return buffer; }
        uint8_t *get() const { return data(); }
        void reset() { length = 0; }
        explicit operator bool() const { return valid(); }
        bool operator!() const { return !valid(); }

        void reset(void *data, size_t size)
        {
            buffer = reinterpret_cast<uint8_t *>(data);
            length = size;
            if (size > SIZE_MAX - reinterpret_cast<uintptr_t>(buffer)) throw std::length_error("memory region too large");
        }

        bool contains(const void *pointer, size_t size = 1) const
        {
            return reinterpret_cast<const uint8_t *>(pointer) >= buffer &&
                contains_offset(reinterpret_cast<const uint8_t *>(pointer) - buffer, size);
        }

        size_t offset_of(const void *pointer) const
        {
            return reinterpret_cast<const uint8_t *>(pointer) >= buffer ? reinterpret_cast<const uint8_t *>(pointer) - buffer : (size_t)-1;
        }

        bool contains_offset(size_t offset) const
        {
            return offset < length;
        }

        bool contains_offset(size_t offset, size_t size) const
        {
            return size <= length && length - size >= offset;
        }

        // Assumes size_bytes is >= sizeof(T)
        template <typename T = void>
        T *at(size_t offset, size_t size_bytes) const
        {
            return contains_offset(offset, size_bytes) ? reinterpret_cast<T *>(buffer + offset) : nullptr;
        }

        template <typename T>
        T *at(size_t offset) const
        {
            return at<T>(offset, sizeof(T));
        }

        template <typename T>
        array_view<T> array_at(size_t offset, size_t num_elements) const
        {
            return { at<T>(offset, num_elements * sizeof(T)), num_elements };
        }

        template <typename T>
        T &ref(size_t offset) const
        {
            auto ptr = at<T>(offset);
            if (!ptr) throw std::out_of_range("invalid buffer offset");
            return *ptr;
        }
    };
}