import { onRequestGet as __api_websites_favorites_js_onRequestGet } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/websites/favorites.js"
import { onRequestPost as __api_websites_favorites_js_onRequestPost } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/websites/favorites.js"
import { onRequestDelete as __api_auth___route___js_onRequestDelete } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/auth/[[route]].js"
import { onRequestGet as __api_auth___route___js_onRequestGet } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/auth/[[route]].js"
import { onRequestPost as __api_auth___route___js_onRequestPost } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/auth/[[route]].js"
import { onRequestPut as __api_auth___route___js_onRequestPut } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/auth/[[route]].js"
import { onRequestGet as __api_websites_index_js_onRequestGet } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/websites/index.js"
import { onRequestPost as __api_websites_index_js_onRequestPost } from "/Users/kess/Documents/GitHub/useful-websites/functions/api/websites/index.js"
import { onRequest as ___middleware_js_onRequest } from "/Users/kess/Documents/GitHub/useful-websites/functions/_middleware.js"

export const routes = [
    {
      routePath: "/api/websites/favorites",
      mountPath: "/api/websites",
      method: "GET",
      middlewares: [],
      modules: [__api_websites_favorites_js_onRequestGet],
    },
  {
      routePath: "/api/websites/favorites",
      mountPath: "/api/websites",
      method: "POST",
      middlewares: [],
      modules: [__api_websites_favorites_js_onRequestPost],
    },
  {
      routePath: "/api/auth/:route*",
      mountPath: "/api/auth",
      method: "DELETE",
      middlewares: [],
      modules: [__api_auth___route___js_onRequestDelete],
    },
  {
      routePath: "/api/auth/:route*",
      mountPath: "/api/auth",
      method: "GET",
      middlewares: [],
      modules: [__api_auth___route___js_onRequestGet],
    },
  {
      routePath: "/api/auth/:route*",
      mountPath: "/api/auth",
      method: "POST",
      middlewares: [],
      modules: [__api_auth___route___js_onRequestPost],
    },
  {
      routePath: "/api/auth/:route*",
      mountPath: "/api/auth",
      method: "PUT",
      middlewares: [],
      modules: [__api_auth___route___js_onRequestPut],
    },
  {
      routePath: "/api/websites",
      mountPath: "/api/websites",
      method: "GET",
      middlewares: [],
      modules: [__api_websites_index_js_onRequestGet],
    },
  {
      routePath: "/api/websites",
      mountPath: "/api/websites",
      method: "POST",
      middlewares: [],
      modules: [__api_websites_index_js_onRequestPost],
    },
  {
      routePath: "/",
      mountPath: "/",
      method: "",
      middlewares: [___middleware_js_onRequest],
      modules: [],
    },
  ]