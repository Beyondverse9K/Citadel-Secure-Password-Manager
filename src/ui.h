#ifndef CITADEL_UI_H
#define CITADEL_UI_H

#include "vault.h"

// Disables terminal echo and prompts for the master password.
void ui_get_master_password(char* buffer, size_t size);

// Displays the main menu and returns the user's choice.
int ui_display_menu();

// Prompts the user for details to add a new credential.
void ui_add_credential_prompt(Vault* vault);

// Prompts the user for a service to find and displays the result.
void ui_find_credential_prompt(const Vault* vault);

// Prompts for a service and deletes it.
void ui_delete_credential_prompt(Vault* vault);

// Lists all credentials in the vault.
void ui_list_all_credentials(const Vault* vault);

// Generates and displays a strong random password.
void ui_generate_password();

#endif //CITADEL_UI_H