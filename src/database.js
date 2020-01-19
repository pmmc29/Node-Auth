const {
    Pool
} = require('pg')


const connectionString = 'postgresql://postgres:pedro123@localhost:5432/test'


const pool = new Pool({
    connectionString: connectionString,
})

const Cnx = async () => {
    try {
        const bd = await pool.query('select current_database()')
        console.log(bd.rows, 'is connected')
    } catch (error) {
        console.log('Error en la conexion con la base de datos')
    }
}

Cnx()

module.exports = pool