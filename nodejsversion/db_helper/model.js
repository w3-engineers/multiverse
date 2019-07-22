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
        id: {
            type: UUID,
            primaryKey: true,
            defaultValue: UUIDV4
        },
        address: {
            type: STRING(50),
        },
        scope: {
            type: STRING(50)
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

    }, {sequelize: DB, indexes:[
            {name: "primary_scope_address", unique: true, fields:["address", "scope"]}
        ]}
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
        {name: "userId_txn", unique: true, fields: ["userId", "txn"]}
    ]});

// User.hasMany(Message, {onDelete: "CASCADE"});
Message.belongsTo(User, {onDelete: "CASCADE"});

module.exports = {User, Message, DB};
