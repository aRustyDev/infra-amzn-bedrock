# modules/monitoring/locals.tf
locals {
  common_tags = merge(var.default_tags, {
    Module = "monitoring"
  })
}
