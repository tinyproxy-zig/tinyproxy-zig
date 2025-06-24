const std = @import("std");

/// Removes any new-line or carriage-return characters from the end of the
/// string. This function is named after the same function in Perl.
///
/// Args:
///   buffer: Mutable slice of bytes to process
///
/// Returns:
///   The number of characters removed from the end of the string.
///   Returns an error if the buffer is invalid.
pub fn chomp(buffer: []u8) !usize {
    if (buffer.len == 0) {
        return error.InvalidLength;
    }

    var chars_removed: usize = 0;
    var length = buffer.len;

    while (length > 0) {
        const idx = length - 1;
        if (buffer[idx] == '\r' or buffer[idx] == '\n') {
            buffer[idx] = 0; // Set to null terminator
            chars_removed += 1;
            length -= 1;
        } else {
            break;
        }
    }

    return chars_removed;
}
