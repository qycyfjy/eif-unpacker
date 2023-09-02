/*
MIT License

Copyright (c) 2020 JeongUkJae

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <locale>
#include <string>
#include <utility>
#include <vector>
#define NOMINMAX
#include <Windows.h>

#define CFB_SIGNATURE "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

#define CFB_SECTOR_MAX_REGULAR_SECTOR 0xFFFFFFFA  // Maximum regular sector number
#define CFB_SECTOR_NOT_APPLICABLE     0xFFFFFFFB  // Reserved for future use
#define CFB_SECTOR_DIFAT_SECTOR       0xFFFFFFFC  // Specifies a DIFAT sector in the FAT.
#define CFB_SECTOR_FAT_SECTOR         0xFFFFFFFD  // Specifies a FAT sector in the FAT.
#define CFB_SECTOR_END_OF_CHAIN       0xFFFFFFFE  // End of a linked chain of sectors.
#define CFB_SECTOR_FREE_SECT          0xFFFFFFFF  // Specifies an unallocated sector in the FAT, Mini FAT, or DIFAT.

#define CFB_DIRECTORY_ENTRY_NO_STREAM 0xFFFFFFFF

namespace CFB {

#pragma pack(push)
#pragma pack(1)

    struct CompoundFileHeader {
        unsigned char signature[8];
        unsigned char unused_classId[16];
        uint16_t minorVersion;
        uint16_t majorVersion;
        uint16_t byteOrder;
        uint16_t sectorShift;
        uint16_t miniSectorShift;
        unsigned char reserved[6];
        uint32_t numDirectorySector;
        uint32_t numFATSector;
        uint32_t firstDirectorySectorLocation;
        uint32_t transactionSignatureNumber;
        uint32_t miniStreamCutoffSize;
        uint32_t firstMiniFATSectorLocation;
        uint32_t numMiniFATSector;
        uint32_t firstDIFATSectorLocation;
        uint32_t numDIFATSector;
        uint32_t headerDIFAT[109];
    };

    // total size: 128 bytes
    struct DirectoryEntry {
        char16_t name[32];
        uint16_t nameLen;
        uint8_t objectType;
        uint8_t colorFlag;
        uint32_t leftSiblingID;
        uint32_t rightSiblingID;
        uint32_t childID;
        unsigned char clsid[16];
        uint32_t stateBits;
        uint64_t creationTime;
        uint64_t modifiedTime;
        uint32_t startSectorLocation;
        uint64_t streamSize;
    };

    struct PropertySetStreamHeader {
        unsigned char byteOrder[2];
        uint16_t version;
        uint32_t systemIdentifier;
        unsigned char clsid[16];
        uint32_t numPropertySets;
        struct {
            char fmtid[16];
            uint32_t offset;
        } propertySetInfo[1];
    };

    struct PropertyIdentifierAndOffset {
        uint32_t id;
        uint32_t offset;
    };

    struct PropertySetHeader {
        uint32_t size;
        uint32_t numProperties;
        PropertyIdentifierAndOffset propertyIdentifierAndOffset[1];
    };

    struct TypedPropertyValue {
        uint16_t type;
        uint16_t padding;
        char value[1];
    };

#pragma pack(pop)

    namespace internal {

        inline uint32_t getUint32Field(const void* address) {
            return *reinterpret_cast<const uint32_t*>(address);
        }

        inline std::string convertUTF16ToUTF8(const char16_t* u16Array) {
            std::wstring wstr(reinterpret_cast<const wchar_t*>(u16Array));
            int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
            std::string str(count, 0);
            WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
            return str;
        }

    }  // namespace internal

    namespace VT {

        // Can be used for VT_BSTR and VT_LPSTR
        //
        // CodePageString Structure
        //  - 4 byte size
        //  - 16-bit characters (null-terminated)
        inline const char16_t* getCodePageString(const TypedPropertyValue* property) {
            return reinterpret_cast<const char16_t*>(property->value + 4);
        }

        inline std::pair<uint32_t, const char16_t*> getCodePageStringWithSize(const TypedPropertyValue* property) {
            return std::pair<uint32_t, const char16_t*>(internal::getUint32Field(property->value), getCodePageString(property));
        }

        // TODO Add more converting functions.

    }  // namespace VT

    enum DirectoryEntryType {
        ENTRY_UNKNOWN_OR_UNALLOCATED = 0,
        ENTRY_STORAGE_OBJECT = 1,
        ENTRY_STREAM_OBJECT = 2,
        ENTRY_ROOT_STORAGE_OBJECT = 5,
    };

    inline bool isStreamObject(const DirectoryEntry* directoryEntry) {
        return directoryEntry->objectType == ENTRY_STREAM_OBJECT;
    }
    inline bool isStorageObject(const DirectoryEntry* directoryEntry) {
        return directoryEntry->objectType == ENTRY_STORAGE_OBJECT;
    }
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-oleps/e5484a83-3cc1-43a6-afcf-6558059fe36e
    // check is property set stream
    inline bool isPropertySetStream(const DirectoryEntry* directoryEntry) {
        return directoryEntry->name[0] == 0x05;
    }

    class CompoundFile {
    public:
        CompoundFile() : buffer(nullptr), bufferLength(0), compoundFileHeader(nullptr), sectorSize(0), miniSectorSize(0), miniStreamStartSector(0) {}
        ~CompoundFile() {}

        void clear() {
            buffer = nullptr;
            bufferLength = 0;
            compoundFileHeader = nullptr;
            sectorSize = 0;
            miniSectorSize = 0;
            miniStreamStartSector = 0;
        }

        void read(const void* buffer, size_t bufferLength) {
            clear();

            if (buffer == NULL || bufferLength < sizeof(CompoundFileHeader))
                throw std::invalid_argument("Buffer is NULL or Buffer Length is zero.");

            this->buffer = reinterpret_cast<const unsigned char*>(buffer);
            this->bufferLength = bufferLength;

            compoundFileHeader = reinterpret_cast<const CompoundFileHeader*>(buffer);
            validateHeader();
            sectorSize = 1 << compoundFileHeader->sectorShift;
            miniSectorSize = 1 << compoundFileHeader->miniSectorShift;

            auto rootDirectoryEntry = getRootDirectoryEntry();
            if (rootDirectoryEntry->creationTime != 0)
                throw std::runtime_error("The Creation Time field in the root directory entry must be zero.");
            miniStreamStartSector = rootDirectoryEntry->startSectorLocation;
        }

        const CompoundFileHeader* getCompoundFileHeader() const { return compoundFileHeader; }

        const DirectoryEntry* getRootDirectoryEntry() const { return getDirectoryEntry(0); }

        // Get Directory Entry
        //
        //
        const DirectoryEntry* getDirectoryEntry(size_t directoryEntryId) const {
            if (directoryEntryId == CFB_DIRECTORY_ENTRY_NO_STREAM)
                return nullptr;

            uint32_t sectorNumber = compoundFileHeader->firstDirectorySectorLocation;
            uint32_t entriesPerSector = sectorSize / sizeof(DirectoryEntry);

            while ((entriesPerSector <= directoryEntryId) && (sectorNumber != CFB_SECTOR_END_OF_CHAIN)) {
                directoryEntryId -= entriesPerSector;
                sectorNumber = getNextFATSectorNumber(sectorNumber);
            }

            auto directoryEntryAddress = getAddressWithSectorNumber(sectorNumber, directoryEntryId * sizeof(DirectoryEntry));
            return reinterpret_cast<const DirectoryEntry*>(directoryEntryAddress);
        }

        std::vector<char> readStreamOfEntry(const DirectoryEntry* entry) const {
            std::vector<char> buffer;
            buffer.resize(entry->streamSize);
            readStreamOfEntry(entry, buffer.data());
            return buffer;
        }

        void readStreamOfEntry(const DirectoryEntry* entry, char* buffer) const {
            if (entry->streamSize < compoundFileHeader->miniStreamCutoffSize)
                readStream(entry->startSectorLocation, entry->streamSize, buffer, miniSectorSize,
                    std::bind(&CompoundFile::getAddressWithMiniSectorNumber, this, std::placeholders::_1, std::placeholders::_2),
                    std::bind(&CompoundFile::getNextMiniFATSectorNumber, this, std::placeholders::_1));
            else
                readStream(entry->startSectorLocation, entry->streamSize, buffer, sectorSize,
                    std::bind(&CompoundFile::getAddressWithSectorNumber, this, std::placeholders::_1, std::placeholders::_2),
                    std::bind(&CompoundFile::getNextFATSectorNumber, this, std::placeholders::_1));
        }

        template <typename CallbackType>
        void iterateAll(CallbackType callback) const {
            iterateNodes(getDirectoryEntry(getRootDirectoryEntry()->childID), 0, callback);
        }

        template <typename CallbackType>
        void iterateFromDirectoryEntry(const DirectoryEntry* directoryEntry, CallbackType callback) const {
            iterateNodes(getDirectoryEntry(directoryEntry->childID), 0, callback);
        }

    private:
        const unsigned char* buffer;
        size_t bufferLength;
        const CompoundFileHeader* compoundFileHeader;
        size_t sectorSize;
        size_t miniSectorSize;
        size_t miniStreamStartSector;

        // Get pointer for sector number and offset
        const void* getAddressWithSectorNumber(uint32_t sectorNumber, uint32_t offset = 0) const {
            if (offset >= sectorSize)
                throw std::invalid_argument("getAddressWithSectorNumber : offset >= sectorSize");

            if (sectorNumber >= CFB_SECTOR_MAX_REGULAR_SECTOR)
                throw std::invalid_argument("getAddressWithSectorNumber : sectorNumber >= CFB_SECTOR_MAX_REGULAR_SECTOR");

            // A sector #0 of the file begins at byte offset Sector Size, not at 0.
            uint64_t bufferOffset = sectorSize * (sectorNumber + 1) + offset;
            if (bufferLength <= bufferOffset)
                throw std::runtime_error("Trying to access out of file");

            return buffer + bufferOffset;
        }

        const void* getAddressWithMiniSectorNumber(uint32_t sectorNumber, uint32_t offset = 0) const {
            if (offset >= miniSectorSize)
                throw std::invalid_argument("getAddressWithSectorNumber : offset >= miniSectorSize, offset: " + std::to_string(offset));

            if (sectorNumber >= CFB_SECTOR_MAX_REGULAR_SECTOR)
                throw std::invalid_argument("getAddressWithSectorNumber : sectorNumber >= CFB_SECTOR_MAX_REGULAR_SECTOR");

            // A mini FAT sector number can be converted into a byte offset into the mini stream by using the following formula: sector number x 64 bytes.
            auto desiredSector = miniStreamStartSector;
            offset = sectorNumber * miniSectorSize + offset;

            while (offset >= sectorSize) {
                desiredSector = getNextFATSectorNumber(desiredSector);
                offset -= sectorSize;
            }

            return getAddressWithSectorNumber(desiredSector, offset);
        }

        // Validate Header when reading a file.
        //
        // 1. check signature
        // 2. check minor version and major version with sector shift
        // 3. check byte order
        // 4. check mini sector shift
        void validateHeader() const {
            if (std::memcmp(compoundFileHeader->signature, CFB_SIGNATURE, 8) != 0)
                throw std::runtime_error("Invalid CFB Signature.");

            if (compoundFileHeader->minorVersion != 0x003E)
                throw std::runtime_error("Minor Version is not 0x003E");

            if (compoundFileHeader->majorVersion != 0x0003 && compoundFileHeader->majorVersion != 0x0004)
                throw std::runtime_error("Major Version should be 3 or 4");

            // If major version is 3, sector shift must be 9, (sector size = 512 bytes)
            // If major version is 4, sector shift must be C, (sector size = 4096 bytes)
            if (((compoundFileHeader->majorVersion == 0x003) ^ (compoundFileHeader->sectorShift == 0x0009)) ||
                (compoundFileHeader->majorVersion == 0x004) ^ (compoundFileHeader->sectorShift == 0x000C))
                throw std::runtime_error("Invalid Sector Shift");

            if (compoundFileHeader->byteOrder != 0xFFFE)
                throw std::runtime_error("Invalid Byte Order");

            if (compoundFileHeader->miniSectorShift != 0x0006)
                throw std::runtime_error("Invalid mini sector shift");
        }

        // Find the next mini sector number by lookup FAT sector.
        //
        // Mini FAT sectors are sotred in the FAT, with the starting location of chain stored in the header.
        uint32_t getNextMiniFATSectorNumber(size_t sectorNumber) const {
            uint32_t entriesPerSector = sectorSize / 4;

            uint32_t miniFATSectorNumber = compoundFileHeader->firstMiniFATSectorLocation;
            while (sectorNumber >= entriesPerSector && miniFATSectorNumber != CFB_SECTOR_END_OF_CHAIN) {
                sectorNumber -= entriesPerSector;
                miniFATSectorNumber = getNextFATSectorNumber(miniFATSectorNumber);
            }

            if (miniFATSectorNumber == CFB_SECTOR_END_OF_CHAIN)
                return CFB_SECTOR_END_OF_CHAIN;

            auto nextMiniSectorNumber = internal::getUint32Field(getAddressWithSectorNumber(miniFATSectorNumber, sectorNumber * 4));
            return nextMiniSectorNumber;
        }

        // Find the next sector number by lookup FAT sectors.
        //
        // Each entry in FAT Sectors contains the sector number of the next sector in the chain.
        // So we can find next sector by lookup desired index in FAT.
        uint32_t getNextFATSectorNumber(size_t sectorNumber) const {
            // 4 = size of a entry (32-bit)
            uint32_t entriesPerSector = sectorSize / 4;
            uint32_t currentFATSector = sectorNumber / entriesPerSector;

            auto currentFATSectorNumber = getFATSectorNumber(currentFATSector);
            auto nextSectorNumber = internal::getUint32Field(getAddressWithSectorNumber(currentFATSectorNumber, (sectorNumber % entriesPerSector) * 4));
            return nextSectorNumber;
        }

        // Get FAT Sector number by lookup the DIFAT Array in a header and DIFAT Sectors
        //
        // TODO: check END_OF_CHAIN Values
        uint32_t getFATSectorNumber(size_t sectorNumber) const {
            // In the header, the DIFAT array occupies 109 entries
            if (sectorNumber < 109)
                return compoundFileHeader->headerDIFAT[sectorNumber];

            // In each DIFAT sector, the DIFAT array occupies the entire sector minus 4 bytes.
            // The last 4 bytes is for chaining the DIFAT sector chain. (Next DIFAT Sector Location)
            size_t entriesPerSector = sectorSize / 4 - 1;
            sectorNumber -= 109;
            uint32_t difatSectorNumber = compoundFileHeader->firstDIFATSectorLocation;

            // If desired sector number is not contained current DIFAT Sector, lookup next DIFAT Sector.
            while (sectorNumber >= entriesPerSector) {
                sectorNumber -= entriesPerSector;
                // In DIFAT Sectors, "Next DIFAT Sector Location" field is at the last.
                difatSectorNumber = internal::getUint32Field(getAddressWithSectorNumber(difatSectorNumber, sectorSize - 4));
            }

            return internal::getUint32Field(getAddressWithSectorNumber(difatSectorNumber, sectorNumber * 4));
        }

        template <typename CallbackType>
        void iterateNodes(const DirectoryEntry* entry, size_t depth, CallbackType callback) const {
            if (entry == nullptr)
                return;

            callback(entry, depth);

            const DirectoryEntry* child = getDirectoryEntry(entry->childID);
            if (child != nullptr)
                iterateNodes(getDirectoryEntry(entry->childID), depth + 1, callback);

            iterateNodes(getDirectoryEntry(entry->leftSiblingID), depth, callback);
            iterateNodes(getDirectoryEntry(entry->rightSiblingID), depth, callback);
        }

        void readStream(uint32_t sectorNumber,
            uint64_t streamSizeToRead,
            char* buffer,
            uint64_t sectorSize,
            std::function<const void* (uint32_t, uint32_t)> addressFn,
            std::function<uint32_t(uint32_t)> nextSectorFn) const {
            size_t bufferPosition = 0;

            while (streamSizeToRead > 0) {
                const void* sourceAddress = addressFn(sectorNumber, 0);
                auto streamSizeToCopy = std::min(sectorSize, streamSizeToRead);
                memcpy(buffer + bufferPosition, sourceAddress, std::min(sectorSize, streamSizeToCopy));

                bufferPosition += streamSizeToCopy;
                streamSizeToRead -= streamSizeToCopy;
                sectorNumber = nextSectorFn(sectorNumber);
            }
        }
    };

    enum VT_Variables : uint16_t {
        VT_EMPTY = 0x0000,             // Undefined, minimum version 0
        VT_NULL = 0x0001,              // NULL, minimum version 0
        VT_I2 = 0x0002,                // 16-bit signed int, minimum version 0
        VT_I4 = 0x0003,                // 32-bit signed int, minimum version 0
        VT_R4 = 0x0004,                // single precision 4-byte IEEE FP number, minimum version 0
        VT_R8 = 0x0005,                // double precision 8-byte IEEE FP number, minimum version 0
        VT_CY = 0x0006,                // CURRENCY, minimum version 0
        VT_DATE = 0x0007,              // DATE, minimum version 0
        VT_BSTR = 0x0008,              // CodePagestring, minimum version 0
        VT_ERROR = 0x000A,             // HRESULT, minimum version 0
        VT_BOOL = 0x000B,              // VARIANT_BOOL, minimum version 0
        VT_DECIMAL = 0x000E,           // DECIMAL, minimum version 0
        VT_I1 = 0x0010,                // 1-byte signed int, minimum version 1
        VT_UI1 = 0x0011,               // 1-byte unsigned int, minimum version 0
        VT_UI2 = 0x0012,               // 2-byte unsigned int, minimum version 0
        VT_UI4 = 0x0013,               // 4-byte unsigned int, minimum version 0
        VT_I8 = 0x0014,                // 8-byte signed int, minimum version 0
        VT_UI8 = 0x0015,               // 8-byte unsigned int, minimum version 0
        VT_INT = 0x0016,               // 4-byte signed int, minimum version 1
        VT_UINT = 0x0017,              // 4-byte unsigned int, minimum version 1
        VT_LPSTR = 0x001E,             // CodePagestring, minimum version 0
        VT_LPWSTR = 0x001F,            // UnicodeString, minimum version 0
        VT_FILETIME = 0x0040,          // FILETIME, minimum version 0
        VT_BLOB = 0x0041,              // Binary Large Object(BLOB), minimum version 0
        VT_STREAM = 0x0042,            // Stream, minimum version 0
        VT_STORAGE = 0x0043,           // Storage, minimum version 0
        VT_STREAMED_OBJECT = 0x0044,   // Stream representing an object in an application specific manner, minimum version 0
        VT_STORED_OBJECT = 0x0045,     // Storage representing an object in an application specific manner, minimum version 0
        VT_BLOB_OBJECT = 0x0046,       // BLOB representing an object in an application-specific manner, minimum version 0
        VT_CF = 0x0047,                // PropertyIdentifier, minimum version 0
        VT_CLSID = 0x0048,             // CLSID, minimum version 0
        VT_VERSIONED_STREAM = 0x0049,  // STREAM with application-specific version GUID(VersionedString), minimum version 0
        VT_VECTOR = 0x1000,            // Vector, minimum version 0
        VT_ARRAY = 0x2000,             // Array, minimum version 1
    };

    // TODO Support Dictionary Property
    class PropertySet {
    public:
        PropertySet(const void* buffer)
            : buffer(reinterpret_cast<const char*>(buffer)), propertySetHeader(reinterpret_cast<const PropertySetHeader*>(buffer)) {}

        uint32_t getPropertySetSize() const { return propertySetHeader->size; }

        uint32_t getNumProperties() const { return propertySetHeader->numProperties; }

        const PropertyIdentifierAndOffset* getPropertyIdentifierAndOffset(size_t index) const {
            if (index >= getNumProperties())
                throw std::invalid_argument("index >= NumProperties");

            return &(propertySetHeader->propertyIdentifierAndOffset[index]);
        }
        const PropertyIdentifierAndOffset* getPropertyIdentifierAndOffset() const { return propertySetHeader->propertyIdentifierAndOffset; }

        const TypedPropertyValue* getPropertyById(uint32_t propertyId) const {
            for (uint32_t i = 0; i < propertySetHeader->numProperties; i++)
                if (propertySetHeader->propertyIdentifierAndOffset[i].id == propertyId)
                    return reinterpret_cast<const TypedPropertyValue*>(buffer + propertySetHeader->propertyIdentifierAndOffset[i].offset);

            return NULL;
        }

        const TypedPropertyValue* getProperty(const PropertyIdentifierAndOffset* propertyIdentifierAndOffset) const {
            return reinterpret_cast<const TypedPropertyValue*>(buffer + propertyIdentifierAndOffset->offset);
        }

    private:
        const char* buffer;
        const PropertySetHeader* propertySetHeader;
        const char* fmtid;
    };

    class PropertySetStream {
    public:
        PropertySetStream(const void* buffer, size_t bufferLength)
            : buffer(reinterpret_cast<const char*>(buffer)),
            propertySetStreamHeader(reinterpret_cast<const PropertySetStreamHeader*>(buffer)),
            bufferLength(bufferLength) {
            auto numPropertySets = getNumPropertySets();

            // A size of PropertySetStream is 28 bytes(from byteorder to numPropertySets) plus 20 bytes(FMTID and offset) * "# of PropertySets", and a size of
            // PropertySet should be at least 8 bytes(size and numProperties).
            if (bufferLength < 28 + 20 * numPropertySets + 8 * numPropertySets)
                throw std::invalid_argument("invalid buffer length");
        }

        uint16_t getPropertySetVersion() const { return propertySetStreamHeader->version; }

        // getNumPropertySets function MUST return either 1 or 2.
        //
        // When NumPropertySets is 1, this stream contains one property set
        // and fields related to property set 2 (FMTID1, Offset1, PropertySet1) are absent.
        uint32_t getNumPropertySets() const { return propertySetStreamHeader->numPropertySets; }

        PropertySet getPropertySet(uint32_t index) const {
            if (index >= getNumPropertySets())
                throw std::invalid_argument("index > num property sets");

            uint32_t offset = propertySetStreamHeader->propertySetInfo[index].offset;
            return PropertySet(buffer + offset);
        }

    private:
        const char* buffer;
        size_t bufferLength;
        const PropertySetStreamHeader* propertySetStreamHeader;
    };

}  // namespace CFB
