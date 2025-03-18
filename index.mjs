//jshint esversion:11
import express from 'express';
import mysql2 from 'mysql2/promise';
import bcrypt from 'bcrypt';
import cors from 'cors';
import cookieParser from 'cookie-parser';
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
app.use(cookieParser());

//Database driver setup
const pool = mysql2.createPool({
	host:'localhost',
	user:'root',
	password:'',//process.env.PASSQL,
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

//Route for checking database
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

//Clients Sign in route
app.post('/login', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
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
    	const token = jwt.sign({ username: user.username, role: 'client' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  		res.cookie('jwt', token, { httpOnly: true, secure: true, path: '/', sameSite: 'lax' });
  		res.status(201).json({ redirect: "/products"});
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/adminlogin", async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
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
    	const token = jwt.sign({ username: user.username, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  		res.cookie('jwt', token, { httpOnly: true, secure: true, path: '/api', sameSite: 'lax' });
  		res.status(201).json({ message: "Admin granted access" });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// JWT verification middleware
function authenticateToken(roles = []) {
  return (req, res, next) => {
    console.log("Authentication middleware started");
    const token = req.cookies.jwt;
    console.log("Token: ",token);

    if (token == null) return res.sendStatus(401); // No token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403); // Invalid token
      req.user = user;
      if (roles.length > 0 && !roles.includes(req.user.role)) {
        console.log('Role mismatch:', req.user.role, 'not in', roles);
        return res.sendStatus(403); // Forbidden due to role mismatch
      }
      next(); // Pass the user to the next middleware or route handler
    });
  };
}

//Redirect route
app.get("/products",authenticateToken(['client','admin']),(req,res) => {
	res.sendFile(import.meta.dirname+"\\templates\\products.html");
});

//Admin routes below
app.get("/api/seeProducts",authenticateToken(['admin']), async (req,res) => {
  
  const connection = await pool.getConnection();
  const [rows] = await connection.execute(
    'SELECT * FROM products'
  );
  connection.release();
  res.json(rows);
});

app.post("/api/addProducts",authenticateToken(['admin']), async (req,res) => {
  
  const { name, price } = req.body;

  const connection = await pool.getConnection();
  await connection.execute(
      'INSERT INTO products (name,price) VALUES (?,?)', [name,price]
    );
    connection.release();
    res.status(201).json({message:"Product added sucessfully."});
});

app.put("/api/chngProduct/:id",authenticateToken(['admin']), async (req,res) => {
  const id = req.params.id;
  const { name, price } = req.body;

  const connection = await pool.getConnection();
  await connection.execute(
      'UPDATE products SET name = ?, price = ? WHERE id = ?', [name,price,id]
    );
    connection.release();
    res.status(201).json({message:"Product changed sucessfully."});
});

app.delete("/api/delProduct/:id",authenticateToken(['admin']), async (req,res) => {

  const id = req.params.id;
  
  const connection = await pool.getConnection();
  const [rows] = await connection.execute(
    'DELETE FROM products WHERE id = ?', [id]
  );
  connection.release();
  res.status(201).json({message:"Product deleted sucessfully."});

});



const port = process.env.PORT;

app.listen(port, () => console.log(`Server running on ${port}...`));