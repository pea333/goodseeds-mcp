const app = require("../index.js");

module.exports = app;
module.exports.handler = (...args) => app(...args);
