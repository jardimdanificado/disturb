#ifndef DISTURB_HOST_IO_H
#define DISTURB_HOST_IO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef char *(*DisturbHostReadFileFn)(const char *path, size_t *out_len);
typedef int (*DisturbHostWriteFileFn)(const char *path, const char *data, size_t len);

/// Read file contents.
///
/// Returns a malloc-allocated buffer (must be freed by caller) or NULL on failure.
/// `out_len` is set to the returned length (0 on failure).
char *disturb_host_read_file(const char *path, size_t *out_len);

/// Write data to a file.
///
/// Returns 1 on success, 0 on failure.
int disturb_host_write_file(const char *path, const char *data, size_t len);

/// Install custom I/O callbacks.
///
/// If `read_fn` or `write_fn` are NULL, the default platform implementation is used.
void disturb_host_set_io_handlers(DisturbHostReadFileFn read_fn, DisturbHostWriteFileFn write_fn);

#ifdef __cplusplus
}
#endif

#endif // DISTURB_HOST_IO_H
