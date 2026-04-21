// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

static const char *type_name(ObjectType t) {
    switch (t) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return "unknown";
    }
}

// Parse type string into ObjectType
static int parse_type(const char *name, ObjectType *out) {
    if (strcmp(name, "blob")   == 0) { *out = OBJ_BLOB;   return 0; }
    if (strcmp(name, "tree")   == 0) { *out = OBJ_TREE;   return 0; }
    if (strcmp(name, "commit") == 0) { *out = OBJ_COMMIT; return 0; }
    return -1;
}

// Write an object to the store.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Build full object: "<type> <size>\0<data>"
    const char *tname = type_name(type);
    char header[64];
    int hlen = snprintf(header, sizeof(header), "%s %zu", tname, len) + 1; // +1 includes NUL

    size_t total = (size_t)hlen + len;
    uint8_t *full = malloc(total);
    if (!full) return -1;
    memcpy(full, header, hlen);
    memcpy(full + hlen, data, len);

    // 2. Compute SHA-256 of the full object
    ObjectID id;
    compute_hash(full, total, &id);

    // 3. Deduplication: if object already exists, skip write
    if (object_exists(&id)) {
        free(full);
        *id_out = id;
        return 0;
    }

    // 4. Create shard directory (.pes/objects/XX/)
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);
    char shard_dir[256];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    // 5. Write to a temporary file in the shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp_XXXXXX", shard_dir);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full); return -1; }

    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, full + written, total - written);
        if (n < 0) {
            close(fd); unlink(tmp_path); free(full);
            return -1;
        }
        written += n;
    }

    // 6. fsync the temp file
    fsync(fd);
    close(fd);
    free(full);

    // 7. Atomic rename to final path
    char final_path[512];
    object_path(&id, final_path, sizeof(final_path));
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    // 8. fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    // 9. Return the hash
    *id_out = id;
    return 0;
}

// Read an object from the store.
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0) { fclose(f); return -1; }

    uint8_t *buf = malloc((size_t)fsize);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);

    // 4. Integrity check: recompute hash and compare
    ObjectID computed;
    compute_hash(buf, fsize, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        fprintf(stderr, "object_read: integrity check failed\n");
        free(buf);
        return -1;
    }

    // 3. Parse header: find the '\0' separating header from data
    uint8_t *nul = memchr(buf, '\0', (size_t)fsize);
    if (!nul) { free(buf); return -1; }

    char type_str[16];
    size_t data_size;
    if (sscanf((char *)buf, "%15s %zu", type_str, &data_size) != 2) {
        free(buf); return -1;
    }

    ObjectType otype;
    if (parse_type(type_str, &otype) != 0) { free(buf); return -1; }

    // 5 & 6. Copy data portion and return
    size_t data_offset = (size_t)(nul - buf) + 1;
    if (data_offset + data_size > (size_t)fsize) { free(buf); return -1; }

    void *data_copy = malloc(data_size + 1);
    if (!data_copy) { free(buf); return -1; }
    memcpy(data_copy, buf + data_offset, data_size);
    ((char *)data_copy)[data_size] = '\0';

    free(buf);
    *type_out = otype;
    *data_out = data_copy;
    *len_out  = data_size;
    return 0;
}
