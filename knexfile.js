// Update with your config settings.

module.exports = {
  development: {
    client: "sqlite3",
    connection: {
      filename: "./knex/db.sqlite3"
    },
    seeds: {
      directory: "./knex/seeds"
    },
    migrations: {
      directory: "./knex/migrations"
    },
    useNullAsDefault: true
  },

  production: {
    client: "postgresql",
    connection: {
      database: "my_db",
      user: "username",
      password: "password"
    },
    pool: {
      min: 2,
      max: 10
    },
    migrations: {
      tableName: "knex_migrations"
    }
  }
};
