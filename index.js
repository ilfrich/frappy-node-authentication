const endpoints = require("./dist/endpoints")

module.exports = {
    registerEndpoints: endpoints.default.registerEndpoints,
    authMiddleware: endpoints.default.authMiddleware,
}
