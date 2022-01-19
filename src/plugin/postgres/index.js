const {Pool} = require('pg')
const params = new URL(process.env.DB_URL)
const config = {
    user: params.username,
    password: params.password,
    host: params.hostname,
    port: params.port || 5432,
    database: params.pathname.split('/')[1],
    ssl: true
};
const pool = new Pool(config)
const bcrypt = require('bcrypt');

const {BasePlugin} = require("..");


/**
 *
 */
class PostgresPlugin extends BasePlugin {
    static initialize(server) {
    }

    /**
     * Create new instance
     *
     * @name constructor
     * @param {*} config
     */
    constructor(server, config) {
        super(...arguments);
    }

    /**
     * Verify the request
     *
     * @name verify
     * @param {*} configToken
     * @param {*} req
     * @param {*} res
     */
    verify(configToken, req, res) {
        const plugin = this;
        let realm = plugin.config.realm
            ? plugin.config.realm
            : "external authentication server";

        // remove garbage
        realm = realm.replace("\\", "");
        realm = realm.replace('"', "");

        return new Promise(resolve => {
            const failure_response = function () {
                res.statusCode = 401;
                res.setHeader("WWW-Authenticate", 'Basic realm="' + realm + '"');
                resolve(res);
            };

            if (!plugin.config.htpasswd) {
                failure_response();
                return;
            }

            if (!req.headers.authorization) {
                failure_response();
                return;
            }

            if (
                !plugin.server.utils.authorization_scheme_is(
                    req.headers.authorization,
                    "basic"
                )
            ) {
                failure_response();
                return;
            }

            const creds = plugin.server.utils.parse_basic_authorization_header(
                req.headers.authorization
            );


            pool
                .connect()
                .then(client => {
                    return client
                        .query('SELECT password FROM basic_auth WHERE username = $1', [creds.username])
                        .then(res => {
                            client.release()
                            let ok = false
                            if (res.rows.length) {
                                ok = bcrypt.compare(creds.password, rows[0].password)
                            }
                            if (ok) {
                                res.statusCode = 200;
                                resolve(res);
                            } else {
                                failure_response();
                            }
                        })
                        .catch(err => {
                            client.release()
                            failure_response()
                            console.log(err)
                        })
                })
        });
    }
}

module.exports = {
    PostgresPlugin
};
