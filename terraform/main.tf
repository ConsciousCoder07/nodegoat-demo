resource "azurerm_resource_group" "my_arm" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "my_sql_server" {
  name                         = "mysqlserver1"
  resource_group_name          = "acceptanceTestResourceGroup1"
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_active_directory_administrator" "my_sql_ad" {
  server_name         = "mysqlserver2"
  resource_group_name = "acceptanceTestResourceGroup1"
  login               = "sqladmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}

resource "azurerm_container_registry" "acr" {
  name                          = "insecureacr12345"
  resource_group_name           = azurerm_resource_group.my_arm.name
  location                      = azurerm_resource_group.my_arm.location
  sku                           = "Basic"
  admin_enabled                 = true
  public_network_access_enabled = true
}
