const {Logger} = require("./helpers/log");
const {User, Message, DB} = require("./db_helper/model");

let logger = new Logger();

User.sync();
logger.v("User Model Sync.");
Message.sync();
logger.v("Message Model Sync.");


