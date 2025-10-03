#ifndef CITADEL_CLIPBOARD_H
#define CITADEL_CLIPBOARD_H

/**
 * Copies text to the system clipboard and clears it after a specified timeout.
 * @param text The text to copy.
 * @param timeout_seconds The number of seconds before the clipboard is cleared.
 */
void clipboard_copy_and_clear(const char* text, int timeout_seconds);

#endif //CITADEL_CLIPBOARD_H