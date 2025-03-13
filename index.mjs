//jshint esversion:11
import express from 'express';
import mysql2 from 'mysql2/promise';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jsonwebtoken from 'jsonwebtoken';

const jwt = jsonwebtoken;

const app = express();
app.use(express.json());
const corsOps = {
  origin: '*', // Replace with your frontend's domain
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true, // Allow cookies to be sent
  optionsSuccessStatus: 204,
};
app.use(cors(corsOps));

//Database driver setup
const pool = mysql2.createPool({
	host:'localhost',
	user:'root',
	password:process.env.PASSQL,
	database: 'auth',
	waitForConnections: true,
  	connectionLimit: 10,
  	queueLimit: 0
});

//DB connection
/*conDB.connect((err) => {
	if (err) {
		console.error(`Error in MySQL connection: ${err.stack}`);
	return;
	}
	console.log(`Connected to MySQL with ID: ${conDB.threadId}.`);

	/*conDB.query("CREATE DATABASE auth", (err,result) => {
		if (err) throw err;
		console.log("Database created");
	});*/

	//let tableQuery = "CREATE TABLE reg_users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))";

	/*conDB.query(tableQuery, (err,result) => {
		if (err) throw err;
		console.log("Table created");
	});*/
//});*/

//Route for basic signin/up page
app.get("/",(req,res) => {
	res.sendFile(import.meta.dirname+"\\templates\\signinup.html");
});

//Route checking database
app.get("/see", async (req,res) => {

    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM reg_users'
    );
    connection.release();
    res.json(rows);

});

//Route to create credentials
app.post("/register", async (req,res) => {
	res.setHeader('Content-Type', 'application/json');
	const {username,password} = req.body;
	const hashedpass = await bcrypt.hash(password,10);

	const connection = await pool.getConnection();
    await connection.execute(
      'INSERT INTO reg_users (username,password) VALUES (?,?)', [username,hashedpass]
    );
    connection.release();
    res.status(201).json({message:"Registered sucessfully."});
});

//Sign in route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM reg_users WHERE username = ?',
      [username]
    );
    connection.release();

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];
    const hashedPasswordFromDB = user.password;

    const passwordMatch = await bcrypt.compare(password, hashedPasswordFromDB);

    if (passwordMatch) {
      //Generate JWT
    	const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  		res.cookie('jwt', token, { httpOnly: true, secure: true });
  		res.status(201).json({ redirect: "/products"});
    } else {
      res.status(401).json({ message: "Invalid credentials"});
    }
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: "Internal server error"});
  }
});

//Redirect route
app.get("/products",(req,res) => {
	res.sendFile(import.meta.dirname+"\\templates\\products.html");
});

const port = process.env.PORT;

app.listen(port, () => console.log(`Server running on ${port}...`));