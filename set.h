#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef SET_H
#define SET_H

// These are pre-defined constants for the FNV Hashing algorithm.
#define FNV_OFFSET 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

// Forward Function Declaration of the FNV_Hashing Fucntion.
static uint64_t FNV_Hashing(void* data, size_t size);

// Defining a Function pointer type for later use.
// Not necessarily needed but keeps code cleaner.
typedef int (*printFN)(const char*, ...);

// The struct definations for the Set datatype. This Set datatype uses "Open Addressing".

// The individual item defination that hold a memory address.
// and hold the size of bytes to read from that address.
typedef struct
{
    unsigned int SSN;
    void* fnPtr;
    unsigned int ordinalNum;
}SetItem;

// The bucket defination, that will hold the hash value as well
// as the pointer to the item.
typedef struct
{
    uint64_t hash;
    // 4 byte padding
    SetItem* item;
}Bucket;

// The actual Set data type that holds a list of buckets and the
// size of the list.
typedef struct
{
    Bucket* buckets;
    size_t count;
}SimpleSet;

// This initializes the set datatype. It declares a list of Bucket datatypes
// which have been zeroed out. 
SimpleSet* CreateSet(size_t size)
{
    SimpleSet* SetArr = (SimpleSet*)malloc(sizeof(SimpleSet));
    SetArr->buckets = (Bucket*)calloc(size, sizeof(Bucket));
    SetArr->count = size;
    return SetArr;
}

// This inserts items into the set. 
void InsertSetBucket(SimpleSet* set, uint64_t hash, unsigned int ordinal )
{
    if (!set) { return; } // If the datatype is not valid. Simply return.

    int index = hash % set->count; // Finding the index to go to within the set bucket list.

    // Trying to find an index that either
    // 1. Has the hash. Which means the item already exists.
    // 2. An Index that is empty that the hash can be inserted in.
    // This is because of "Open Addressing".
    while (set->buckets[index].hash != hash && set->buckets[index].item != NULL)
    {
        index = (index + 1) % set->count;
    }
    if (set->buckets[index].hash == hash) { return; } // If set already exists, do nothing.

    SetItem* NewItem = (SetItem*)malloc(sizeof(SetItem));
    NewItem->ordinalNum = ordinal;
    set->buckets[index].hash = hash;
    set->buckets[index].item = NewItem;
}

void InsertSetItem(SimpleSet* set, uint64_t hash , void* fnPtr, unsigned int SSN)
{
    if (!set) { return; }

    int index = hash % set->count; // Finding the index to go to within the set bucket list.

    // Trying to find an index that either
    // 1. Has the hash. Which means the item already exists.
    // 2. An Index that is empty that the hash can be inserted in.
    // This is because of "Open Addressing".
    while (set->buckets[index].hash != hash && set->buckets[index].item != NULL)
    {
        index = (index + 1) % set->count;
    }
    if (set->buckets[index].item == NULL) 
    {
        SetItem* NewItem = (SetItem*)malloc(sizeof(SetItem));
        set->buckets->item = NewItem;
        set->buckets[index].hash = hash;
    }
    set->buckets[index].item->fnPtr = fnPtr;
    set->buckets[index].item->SSN = SSN;
}


// This finds and returns the setItem. 
SetItem* GetSetItem(SimpleSet* set, uint64_t hash)
{
    if (!set) { return NULL; }

    int index = hash % set->count;
    while (set->buckets[index].hash != hash && set->buckets[index].item != NULL)
    {
        index = (index + 1) % set->count;
    }
    // If the SetItem is equal to NULL, this means that this item does not exist
    // in the hash table.
    if (set->buckets[index].item == NULL) { return NULL; }

    return set->buckets[index].item;
}

uint64_t FNV_Hashing(void* data, size_t size)
{
    uint8_t* ptr = (uint8_t*)data;
    uint64_t hash = FNV_OFFSET;
    for (size_t i = 0; i < size; i++)
    {
        hash = hash ^ ptr[i];
        hash = hash * FNV_PRIME;
    }
    return hash;
}


#endif