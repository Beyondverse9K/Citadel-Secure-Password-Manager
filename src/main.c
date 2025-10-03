#include <stdio.h>
#include <stdlib.h>
#include "security.h"
#include "vault.h"
#include "ui.h"

int main() {

    security_perform_checks();

    char master_password[256];
    ui_get_master_password(master_password, sizeof(master_password));

    Vault* vault = vault_load(master_password);
    if (!vault) {
        return EXIT_FAILURE;
    }
    printf("Vault loaded successfully. %zu entries found.\n", vault->count);

    int choice = 0;
    while (choice != 6) {
        choice = ui_display_menu();
        switch (choice) {
            case 1:
                ui_list_all_credentials(vault);
                break;
            case 2:
                ui_find_credential_prompt(vault);
                break;
            case 3:
                ui_add_credential_prompt(vault);
                break;
            case 4:
                ui_delete_credential_prompt(vault);
                break;
            case 5:
                ui_generate_password();
                break;
            case 6:
                printf("Saving vault and exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    if (vault_save(vault, master_password) == 0) {
        printf("Vault saved successfully.\n");
    } else {
        printf("Error: Could not save the vault.\n");
    }

    vault_free(vault);
    
    return EXIT_SUCCESS;
}