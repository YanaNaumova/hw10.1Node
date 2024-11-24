import express from "express";
import "dotenv/config";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const users = [
  {
    id: 1,
    email: "example1@gmail.com",
    password: await bcrypt.hash("user1", 5),
    username: "example1",
  },
  {
    id: 2,
    email: "example2@gmail.com",
    password: await bcrypt.hash("user2", 5),
    username: "example2",
  },
  {
    id: 3,
    email: "example3@gmail.com",
    password: await bcrypt.hash("user3", 5),
    username: "example3",
  },
];
const port = process.env.PORT;
const jwtSecret = process.env.JWT_SECRET;
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(403).json({ message: "All fields are required" });
    }
    const user = users.find((user) => user.email === email);
    if (!user) {
      return res.status(404).json({ message: "user was not found" });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: "Incorrect password" });
    }
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      jwtSecret,
      { expiresIn: "1h" }
    );
    res.status(200).json({ token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/refresh-token", (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, jwtSecret, (err, data) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Forbidden: Invalid or required token" });
      }
      const newToken = jwt.sign(
        {
          id: data.id,
          email: data.email,
          username: data.username,
        },
        jwtSecret,
        { expiresIn: "1h" }
      );
      res.status(200).json({ newToken });
    });
  } else {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://127.0.0.1:${port}`);
});
