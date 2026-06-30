"""Route Management module for VVRP."""

from .commands import RM_register_commands
from .models import RMRoute, RMRouteSource
from .rib import (
    RM_route_table,
    RM_IPv4RadixTree,
    RM_RouteTable,
    RM_route_table_from_routes,
)
from .routes import (
    RM_connected_routes,
    RM_connected_routes_from_im,
    RM_lookup_route,
    RM_register_route_event_handlers,
    RM_route_table_from_im,
)
from .state import RM_clear_router_id, RM_router_id, RM_set_router_id
from .static import (
    RM_StaticRouteConfig,
    RM_remove_static_route_configs,
    RM_set_static_route_config,
    RM_static_route_configs,
    RM_sync_static_routes,
)

__all__ = [
    "RM_register_commands",
    "RM_register_route_event_handlers",
    "RM_IPv4RadixTree",
    "RMRoute",
    "RM_RouteTable",
    "RMRouteSource",
    "RM_connected_routes",
    "RM_connected_routes_from_im",
    "RM_lookup_route",
    "RM_route_table",
    "RM_route_table_from_im",
    "RM_route_table_from_routes",
    "RM_router_id",
    "RM_set_router_id",
    "RM_clear_router_id",
    "RM_StaticRouteConfig",
    "RM_remove_static_route_configs",
    "RM_set_static_route_config",
    "RM_static_route_configs",
    "RM_sync_static_routes",
]
