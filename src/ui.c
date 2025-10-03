#include "ui.h"
#include "clipboard.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>


static void get_input(char* buffer, size_t size) {
    fgets(buffer, (int)size, stdin);
    buffer[strcspn(buffer, "\n")] = 0; // Remove trailing newline
}

void ui_get_master_password(char* buffer, size_t size) {
    printf("Enter Master Password: ");
    fflush(stdout);

    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO; // Disable terminal echo
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    get_input(buffer, size);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term); // Restore terminal settings
    printf("\n");
}

int ui_display_menu() {
    printf("\n--- Citadel Password Manager ---\n");
    printf("1. List all credentials\n");
    printf("2. Find and copy a password\n");
    printf("3. Add a new credential\n");
    printf("4. Delete a credential\n");
    printf("5. Generate a strong password\n");
    printf("6. Save and Exit\n");
    printf("--------------------------------\n");
    printf("Enter your choice: ");

    char choice_str[10];
    get_input(choice_str, sizeof(choice_str));
    return atoi(choice_str);
}

void ui_add_credential_prompt(Vault* vault) {
    char service[256], username[256], password[256];
    printf("Enter service name: ");
    get_input(service, sizeof(service));
    printf("Enter username: ");
    get_input(username, sizeof(username));
    printf("Enter password: ");
    get_input(password, sizeof(password));

    vault_add_credential(vault, service, username, password);
    printf("Credential for '%s' added.\n", service);
}

void ui_find_credential_prompt(const Vault* vault) {
    char service[256];
    printf("Enter service name to find: ");
    get_input(service, sizeof(service));
    
    Credential* cred = vault_find_credential(vault, service);
    if (cred) {
        printf("Found credential for '%s'\n", cred->service);
        printf("  Username: %s\n", cred->username);
        clipboard_copy_and_clear(cred->password, 30);
    } else {
        printf("No credential found for '%s'.\n", service);
    }
}

void ui_delete_credential_prompt(Vault* vault) {
    char service[256];
    printf("Enter service name to delete: ");
    get_input(service, sizeof(service));
    vault_delete_credential(vault, service);
}

void ui_list_all_credentials(const Vault* vault) {
    printf("\n--- Stored Credentials ---\n");
    if (vault->count == 0) {
        printf("The vault is empty.\n");
    } else {
        for (size_t i = 0; i < vault->count; ++i) {
            printf("Service: %s (Username: %s)\n", vault->credentials[i].service, vault->credentials[i].username);
        }
    }
}

void ui_generate_password() {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;";
    const int charset_size = sizeof(charset) - 1;
    const int password_length = 20;

    char password[password_length + 1];
    
    FILE* urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        perror("Error opening /dev/urandom");
        return;
    }
    
    for (int i = 0; i < password_length; ++i) {
        password[i] = charset[fgetc(urandom) % charset_size];
    }
    password[password_length] = '\0';
    fclose(urandom);
    
    printf("\nGenerated Password: %s\n", password);
    clipboard_copy_and_clear(password, 30);
}