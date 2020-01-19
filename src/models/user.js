const bcrypt = require('bcrypt-nodejs')
const pool = require('../database')


let users = []

const cargarUsuarios = async () => {
    const response = await pool.query('select * from usuarios')
    users = response.rows
    console.log(users)
}
console.log('asdasd')

cargarUsuarios()


class User {
    constructor() {
        this.id = ''
        this.email = ''
        this.password = ''
    }


    async encryptPassword(password) {
        return await bcrypt.hashSync(password, bcrypt.genSaltSync(10))

    }

    async comparePassword(password) {
        return await bcrypt.compareSync(password)
    }

    async insertUser(email, password) {
        const response = await pool.query('insert into usuarios (email, pass) values ($1, $2)', [email, password])

        // console.log(response)
        console.log(email, password)
    }

    async findById(id) {
        const response = await pool.query('select * from usuarios where id = $1', [id])
        console.log(response.rows)
    }
}


module.exports = User