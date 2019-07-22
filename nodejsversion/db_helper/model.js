const {Sequelize, Model, TEXT, STRING, BOOLEAN, DATE, NOW, UUIDV4, UUID} = require("sequelize");
const CONFIG = require("../config");

const DB = new Sequelize(CONFIG.DB_NAME, CONFIG.DB_USR, CONFIG.DB_PWD, {
  host: CONFIG.DB_HOST,
  dialect: CONFIG.DB_PROVIDER
});


class User extends Model {
}

User.init(
    {
        address: {
            type: STRING(42),
            primaryKey: true
        },
        sid: {
            type: STRING(50),
            unique: true
        },
        is_online:{
            type: BOOLEAN,
            allowNull: false,
            defaultValue: 1
        }

    }, {sequelize: DB}
);

class Message extends Model{
}

Message.init({
    id: {
        primaryKey: true,
        type: DATE,
        defaultValue: NOW
    },
    txn:{
        type: STRING(50)
    },
    message:{
        type: TEXT()
    },
    status:{
        type: BOOLEAN,
        defaultValue:0
    }
}, {sequelize: DB, indexes:[
        {name: "userId_txn", unique: true, fields: ["userAddress", "txn"]}
    ]});

// User.hasMany(Message, {onDelete: "CASCADE"});
Message.belongsTo(User, {onDelete: "CASCADE"});

module.exports = {User, Message, DB};
