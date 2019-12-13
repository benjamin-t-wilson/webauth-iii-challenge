const db = require("../../data/dbConfig.js");

function addUser(user) {
  // takes an argument, expected object
  return db("users") // addressing users table
    .insert(user) // inserting arg object into addressed table ( users )
    .then(res => {
      // initializes a promise
      return res; // will be the id
    });
}

function findBy(key) {
  // takes an arugment
  return db("users") // addresses the users table
    .where(key) // where the key matches the corresponding column
    .first(); // returns the first item
}

function getUsers() {
  return db("users"); // implies .select("*").from("users")
}

module.exports = {
  addUser,
  findBy,
  getUsers
};
