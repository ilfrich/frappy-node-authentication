import randomstring from "randomstring"

/**
 * Retrieves the Authorization header from the request
 * @param {object} req - the current REST request
 * @returns {string} the header value or null
 */
const getAuthHeader = req => (req.headers ? req.headers.authorization : null)

/**
 * Express middleware that performs a check on the Authorization header of the incoming request and checks for required
 * permissions, if the user is authenticated. It will also clean up expired authorization token, if it encounters them.
 * @param {string | Object} requiredPermissions - a single permission provided as string or a list of permissions
 * provided as array (user has to fulfill all)
 * @param {Object} tokenCache - the global auth token cache that contains all active auth tokens and maps to the
 * corresponding user object and the expiration time of the token.
 * @param {boolean} allowApiKey - a boolean that allows API key access for endpoints protected with this middleware
 * @returns {null} in case the authentication fails
 */
const authMiddleware = (requiredPermissions, tokenCache, allowApiKey = false) => (req, res, next) => {
    const authHeader = getAuthHeader(req)
    if (authHeader == null) {
        // no auth header
        res.status(401).send({
            status: "Not Authorized",
        })
        return
    }

    if (tokenCache == null || tokenCache.token == null) {
        // no cache provided, this is a coding error
        console.log("[ERROR] Please provide a token cache (JSON object `{}`) to the auth middleware")
        res.status(500).send({
            status: "Server error during authentication check",
        })
        return
    }

    let currentUser = null

    if (authHeader.startsWith("Token ")) {
        // api key login
        if (allowApiKey === true) {
            // check if we have an API token
            const apiKey = authHeader.substring(6)
            if (tokenCache.keys != null && tokenCache.keys[apiKey] != null) {
                // all good
                currentUser = tokenCache.keys[apiKey]
            } else {
                res.status(401).send({ status: "Not Authorized" })
                return
            }
        } else {
            res.status(403).send({ status: "Auth method not allowed" })
            return
        }
    } else {
        // regular login
        if (tokenCache.token[authHeader] == null) {
            res.status(401).send({
                status: "Not Authorized",
            })
            return
        }

        // fetch user from cache
        const { user, expires } = tokenCache.token[authHeader]

        if (expires < new Date().getTime()) {
            // login expired
            delete tokenCache.token[authHeader]
            // we don't need to clean up the userTokenStore here, since that will be done on next startup, and no read is
            // performed in the meantime
            res.status(440).send({
                status: "Session expired",
            })
            return
        }

        currentUser = user
    }

    if (currentUser == null) {
        // general error (unlikely)
        res.status(401).send({
            status: "Not Authorized",
        })
        return
    }

    if (requiredPermissions != null) {
        // check permission
        if (typeof requiredPermissions === "string") {
            // single permission
            if (currentUser.permissions == null || currentUser.permissions.indexOf(requiredPermissions) === -1) {
                // permission not found
                res.status(403).send({
                    status: "Forbidden",
                })
                return
            }
        } else if (requiredPermissions.length > 0 && requiredPermissions.forEach != null) {
            // list of permissions
            let missingPerms = false
            requiredPermissions.forEach(requiredPermission => {
                if (currentUser.permissions == null || currentUser.permissions.indexOf(requiredPermission) === -1) {
                    // permission not found
                    missingPerms = true
                }
            })
            if (missingPerms === true) {
                res.status(403).send({
                    status: "Forbidden",
                })
                return
            }
        } else {
            // requiredPermissions is not an array or a string
            console.log(
                "You have provided required permissions to the middleware, but the permissions are neither a single string nor an array."
            )
            res.status(500).send({
                status: "Server error during authentication check",
            })
            return
        }
    }

    // all good
    req.currentUser = currentUser
    next()
}

/**
 * Initialises the tokenCache on startup with previously logged in users (after restart of the application). The
 * function will also delete any expired user tokens before populating the token cache
 * @param {Object} tokenCache - the token cache, which is a JSON object mapping from token to the user information (user
 * and expiration)
 * @param {Object} userTokenStore - a MongoDB or MySQL store implementing the userTokenStore interface
 * @param {Object} userStore - a MongoDB or MySQL store implementation of the userStore interface
 * @param {number} tokenDuration - the number of seconds a token is valid for
 * @param {boolean} useApiKeys - a boolean flag to indicate whether to load api key users as well
 */
const initTokenCache = (tokenCache, userTokenStore, userStore, tokenDuration, useApiKeys) => {
    tokenCache.token = {}
    const deletedUserTokens = []
    // delete any token older than this
    userTokenStore
        .removeExpired(new Date().getTime() - tokenDuration * 1000)
        // fetch all remaining token records (with increased page size, will return very small records)
        .then(() => userTokenStore.getAll({ pageSize: 500, page: 0 }))
        .then(allTokens => {
            const allPromises = []
            allTokens.forEach(tokenRecord => {
                // fetch corresponding user
                allPromises.push(
                    userStore.get(tokenRecord.userId).then(user => {
                        if (user == null) {
                            // user probably deleted, remember token to delete and skip further execution
                            deletedUserTokens.push(tokenRecord.token)
                            return
                        }
                        if (user.password != null) {
                            // for native users, delete the password from the user profile
                            delete user.password
                        }
                        // add user and expiration date to cache
                        tokenCache.token[tokenRecord.token] = {
                            user,
                            expires: tokenRecord.creationTimestamp + tokenDuration * 1000,
                        }
                    })
                )
            })
            return Promise.all(allPromises)
        })
        .then(() => {
            deletedUserTokens.forEach(token => {
                userTokenStore.removeToken(token)
            })
        })
        .then(() => {
            if (useApiKeys === true) {
                tokenCache.keys = {}
                return userStore.getUsersWithApiKey()
            }
            return []
        })
        .then(apiKeyUsers => {
            apiKeyUsers.forEach(user => {
                tokenCache.keys[user.apiKey] = user
            })
        })
}

/**
 * Deletes tokens from the token cache for a given user. This is usually necessary when a user gets deleted to
 * immediately invalidate all existing login sessions.
 * @param {Object} tokenCache - a JSON object mapping from login tokens to user information
 * @param {string} userId - the id of the user to remove all tokens from the cache for
 * @param {Object} userTokenStore - optional store class holding active user auth tokens
 */
const cleanupTokenCache = (tokenCache, userId, userTokenStore) => {
    // storage for tokens to be deleted to avoid manipulation of the list while iterating
    const deleteTokens = []
    Object.keys(tokenCache.token).forEach(token => {
        if (
            (tokenCache.token[token].user != null && tokenCache.token[token].user._id.toString() === userId) ||
            tokenCache.token[token].user.id === userId
        ) {
            // found a match for this user
            deleteTokens.push(token)
        }
    })

    // clean up all tokens
    deleteTokens.forEach(token => {
        delete tokenCache.token[token]
        if (userTokenStore != null) {
            userTokenStore.removeToken(token)
        }
    })
    // handle api keys
    if (tokenCache.keys != null) {
        const deleteKeys = []
        Object.keys(tokenCache.keys).forEach(apiKey => {
            if (tokenCache.keys[apiKey]._id.toString() === userId || tokenCache.keys[apiKey].user.id === userId) {
                deleteKeys.push(apiKey)
            }
        })
        deleteKeys.forEach(key => {
            delete tokenCache.keys[key]
        })
    }
}

/**
 * Updates the token cache with an updated user profile. This ensures updated permissions for the authentication check
 * and middleware are effective from the moment they have been made.
 * @param {Object} tokenCache - a JSON object mapping from login tokens to user information
 * @param {Object} updatedUser - the updated user object to store in the token cache, if the user has active tokens.
 */
const updateTokenCache = (tokenCache, updatedUser) => {
    Object.keys(tokenCache.token).forEach(token => {
        if (
            tokenCache.token[token] != null &&
            tokenCache.token[token].user._id.toString() === updatedUser._id.toString()
        ) {
            tokenCache.token[token].user = updatedUser
        }
    })

    if (tokenCache.keys != null) {
        Object.keys(tokenCache.keys).forEach(apiKey => {
            if (tokenCache.keys[apiKey]._id.toString() === updatedUser._id.toString()) {
                tokenCache.keys[apiKey] = updatedUser
            }
        })
    }
}

/**
 * Registers the login endpoints and - unless otherwise indicated via the options - the user management endpoints to
 * create, delete and update user records.
 * @param {Object} expressApp - the main express app running your server
 * @param {Object} userStore - a MongoDB or MySQL store implementation of the userStore interface
 * @param {Object} userTokenStore - a MongoDB or MySQL store implementing the userTokenStore interface
 * @param {Object} tokenCache - the token cache, which is a JSON object mapping from token to the user information (user
 * and expiration)
 * @param {Object} options - optional options for this module. Available options can be found below in the first lines
 * of this function: apiPrefix, tokenExpiration, adminPermission, defaultPermissions, noUserManagement,
 */
const registerEndpoints = (expressApp, userStore, userTokenStore, tokenCache, options = {}) => {
    // extract options
    const apiPrefix = options.apiPrefix || "/api/user"
    const tokenDuration = options.tokenExpiration || 60 * 60 * 24 * 14 // default: 14 days
    const userAdminPermission = options.adminPermission || "admin"
    const defaultPermissions = options.defaultPermissions || [] // default: no permissions
    const noUserManagement = options.noUserManagement === true
    const useApiKeys = options.apiKeys === true
    const allowOwnProfileEdit = options.allowOwnProfileEdit || false
    const pageSize = options.pageSize || 25

    if (tokenCache == null) {
        throw Error("tokenCache cannot be null")
    }
    if (expressApp == null) {
        throw Error("expressApp cannot be null")
    }
    if (userStore == null) {
        throw Error("userStore cannot be null")
    }

    if (userTokenStore != null) {
        initTokenCache(tokenCache, userTokenStore, userStore, tokenDuration, useApiKeys)
    }

    // check authentication endpoint
    expressApp.get(apiPrefix, authMiddleware(null, tokenCache), (req, res) => {
        // send back current user
        res.send(req.currentUser)
    })

    // logout endpoint
    expressApp.delete(`${apiPrefix}/login`, authMiddleware(null, tokenCache), (req, res) => {
        const token = getAuthHeader(req)
        delete tokenCache.token[token]
        if (userTokenStore != null) {
            // can finish in the background
            userTokenStore.removeToken(token)
        }
        res.send({ status: true })
    })

    // login endpoint
    expressApp.post(`${apiPrefix}/login`, (req, res) => {
        if (
            req.body == null ||
            req.body.username == null ||
            req.body.password == null ||
            req.body.username.trim() === ""
        ) {
            res.status(400).send({
                status: "Invalid request",
            })
            return
        }

        const { username, password } = req.body

        userStore
            .login(username, password)
            .then(currentUser => {
                if (currentUser == null) {
                    res.status(401).send({
                        status: "Not Authorized",
                    })
                    return
                }

                // create token and add to tokenCache
                const newToken = randomstring.generate(24)
                if (userTokenStore != null) {
                    userTokenStore.storeToken(newToken, currentUser)
                }
                tokenCache.token[newToken] = {
                    expires: new Date().getTime() + tokenDuration * 1000,
                    user: currentUser,
                }

                res.send({
                    user: currentUser,
                    token: newToken,
                })
            })
            .catch(err => {
                console.log("Error during login procedure", err)
                res.status(500).send({
                    status: "Server error during authentication check",
                })
            })
    })


    // change password for local user
    expressApp.post(`${apiPrefix}/password`, authMiddleware(null, tokenCache), (req, res) => {
        const { body } = req
        if (
            body.oldPassword == null ||
            body.oldPassword.trim() === "" ||
            body.newPassword == null ||
            body.newPassword.trim() === ""
        ) {
            res.status(400).send({ status: "Invalid password provided" })
            return
        }

        // check that the old password is correct
        userStore.login(req.currentUser.username, body.oldPassword).then(loggedInUser => {
            if (loggedInUser == null) {
                // old password didn't match
                res.status(403).send({ status: "Invalid password" })
                return
            }
            const userId = loggedInUser._id || loggedInUser.id

            userStore
                .changePassword(userId, body.newPassword)
                .then(() => userStore.get(userId))
                .then(updatedUser => {
                    delete updatedUser.password
                    res.send(updatedUser)
                })
                .catch(err => {
                    console.log("Error changing password", err)
                    res.status(500).send({ status: "Password update failed" })
                })
        })
    })

    if (useApiKeys === true) {
        // endpoints for managing api keys
        expressApp.post(`${apiPrefix}/key`, authMiddleware(null, tokenCache), (req, res) => {
            // create key
            userStore
                .createApiKey(req.currentUser._id.toString())
                .then(newKey => {
                    if (tokenCache.keys != null) {
                        if (req.currentUser.apiKey != null && tokenCache.keys[req.currentUser.apiKey] != null) {
                            // remove old key
                            delete tokenCache.keys[req.currentUser.apiKey]
                        }
                        // add new key to cache
                        const newUser = { ...req.currentUser }
                        newUser.apiKey = newKey
                        tokenCache.keys[newKey] = newUser
                        updateTokenCache(tokenCache, newUser)
                    }
                    res.send({ apiKey: newKey })
                })
                .catch(err => {
                    console.log("Error creating API key", err)
                    res.status(500).send({
                        status: "Create API key failed",
                    })
                })
        })

        expressApp.delete(`${apiPrefix}/key`, authMiddleware(null, tokenCache), (req, res) => {
            // revoke key
            userStore.revokeApiKey(req.currentUser._id.toString())
            if (
                req.currentUser.apiKey != null &&
                tokenCache != null &&
                tokenCache.keys != null &&
                tokenCache.keys[req.currentUser.apiKey] != null
            ) {
                delete tokenCache.keys[req.currentUser.apiKey]
            }
            const updatedUser = { ...req.currentUser }
            delete updatedUser.apiKey
            updateTokenCache(tokenCache, updatedUser)
            res.send({ apiKey: null })
        })
    }

    if (noUserManagement) {
        // all endpoints declared, skip the rest
        return
    }

    const userAdminMiddleware = authMiddleware(userAdminPermission, tokenCache)

    // fetch all users
    expressApp.get(`${apiPrefix}/users`, userAdminMiddleware, (req, res) => {
        const page = req.query.page || 0
        userStore.getAll({ page, pageSize }).then(allUsers => {
            res.send(
                allUsers.map(user => {
                    if (user.password != null) {
                        delete user.password
                    }
                    return user
                })
            )
        })
    })

    // update user permissions
    expressApp.post(`${apiPrefix}/users/:userId/permissions`, userAdminMiddleware, (req, res) => {
        const { permissions } = req.body
        const { userId } = req.params
        userStore
            .get(userId)
            .then(existingUser => {
                // user not found, return 404
                if (existingUser == null) {
                    res.status(404).send()
                    return null
                }

                // update permission, token cache and return updated user
                return userStore
                    .updatePermissions(existingUser._id, permissions)
                    .then(() => userStore.get(userId))
                    .then(updatedUser => {
                        updateTokenCache(tokenCache, updatedUser)
                        delete updatedUser.password
                        res.send(updatedUser)
                    })
            })
            .catch(err => {
                console.log("Error updating user permissions", err)
                res.status(500).send({ status: "Permission update failed" })
            })
    })

    // update user profile
    expressApp.post(`${apiPrefix}/users/:userId/profile`, authMiddleware(null, tokenCache), (req, res) => {
        const { currentUser, body } = req
        if (currentUser.permissions.indexOf(userAdminPermission) === -1) {
            if (allowOwnProfileEdit === false) {
                res.status(403).send()
                return
            }
            const userId = currentUser._id || currentUser.id
            if (req.params.userId !== `${userId}`) {
                res.status(403).send()
                return
            }
        }
        // update profile
        userStore
            .get(req.params.userId)
            .then(existingUser => {
                if (existingUser == null) {
                    res.status(404).send()
                    return null
                }
                return userStore.updateProfile(existingUser._id, body).then(updatedUser => {
                    delete updatedUser.password
                    res.send(updatedUser)
                })
            })
            .catch(err => {
                console.log("Error updating user profile", err)
                res.status(500).send({ status: "Profile updated failed" })
            })
    })

    // delete user
    expressApp.delete(`${apiPrefix}/users/:userId`, userAdminMiddleware, (req, res) => {
        const { userId } = req.params
        userStore.get(userId).then(existing => {
            if (existing == null) {
                res.status(404).send()
                return
            }

            // delete user and send back user ID and status
            userStore.delete(userId).then(() => {
                // clean up tokenCache
                cleanupTokenCache(tokenCache, userId, userTokenStore)

                res.send({
                    userId,
                    deleted: true,
                })
            })
        })
    })

    // create user
    expressApp.post(`${apiPrefix}/users`, userAdminMiddleware, (req, res) => {
        const { body } = req
        // local user
        const newUser = {
            username: body.username,
            password: body.password,
            permissions: body.permissions || defaultPermissions,
            profile: {},
        }

        if (
            newUser.username == null ||
            newUser.password == null ||
            newUser.username.trim() === "" ||
            newUser.password.trim() === ""
        ) {
            // missing username or password
            res.status(400).send({
                status: "Missing username/password",
            })
            return
        }

        // check if username already exists
        userStore.getByUsername(newUser.username).then(existing => {
            if (existing != null) {
                // user already exists
                res.status(400).send({
                    status: "Duplicate username",
                })
                return
            }
            // create user and send response
            userStore
                .createLocalUser(newUser.username, newUser.password, newUser.permissions)
                .then(createdUser => {
                    delete createdUser.password
                    res.send(createdUser)
                })
                .catch(err => {
                    console.log("Error creating user", err)
                    res.status(500).send({
                        status: "Error creating user",
                    })
                })
        })
    })

    // update a users password
    expressApp.post(`${apiPrefix}/users/:userId/password`, userAdminMiddleware, (req, res) => {
        const { body } = req
        const { userId } = req.params
        if (body.password == null || body.password.trim() === "") {
            res.status(400).send({ status: "Invalid password provided" })
            return
        }
        let responseSent = false
        userStore
            .get(userId)
            .then(existing => {
                if (existing == null) {
                    res.status(404).send({ status: "Not found" })
                    responseSent = true // prevent re-sending response
                    throw Error("User not found")
                }
                return userStore.changePassword(existing._id, body.password)
            })
            .then(() => userStore.get(userId))
            .then(updatedUser => {
                delete updatedUser.password
                res.send(updatedUser)
            })
            .catch(err => {
                if (responseSent === false) {
                    console.log("Error updating user's password", err)
                    res.status(500).send({ status: "Password update failed" })
                }
            })
    })
}

// only the authMiddleware and endpoints are exported
export default {
    registerEndpoints,
    authMiddleware,
}
