const db = require("../../data/dbConfig.js");

function addUser(user) {
  return db("users")
    .insert(user)
    .then(res => {
      return res;
    });
}

function findBy(key) {
  return db("users")
    .where(key)
    .first();
}

function getUsers() {
  return db("users");
}

module.exports = {
  addUser,
  findBy,
  getUsers
};
