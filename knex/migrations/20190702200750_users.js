exports.up = function(knex) {
  return knex.schema.createTable("users", table => {
    table.increments("id");
    table
      .string("email")
      .notNullable()
      .unique();
    table.string("password").notNullable();
    table.string("avatar");
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists("users");
};
