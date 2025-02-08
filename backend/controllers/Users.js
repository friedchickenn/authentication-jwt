import Users from "../models/UserModel.js";
import bcrypt from 'bcrypt'; 
import jwt from 'jsonwebtoken';

export const getUsers = async (req, res) => {
    try {
        const users = await Users.findAll({
            attributes: ['id', 'name', 'email'] 
        });
        res.json(users);
    } catch (error) {
        console.error("Error getting users:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

export const Register = async (req, res) => {
    const { name, email, password, confPassword } = req.body;

    console.log("Request Body:", req.body); // Debug data yang diterima

    if (password !== confPassword) return res.status(400).json({ message: "Password tidak cocok" });

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    try {
        const newUser = await Users.create({
            name,
            email,
            password: hashPassword
        });
        console.log("User created:", newUser); // Debug user yang dibuat
        res.status(201).json({ message: "Register Berhasil" });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};


export const Login = async (req, res) => {
    try {
        const user = await Users.findOne({ 
            where: {
                email: req.body.email
            }
        });

        if (!user) return res.status(404).json({ message: "Email tidak ditemukan" });

        const match = await bcrypt.compare(req.body.password, user.password);
        if (!match) return res.status(400).json({ message: "Password Salah" });

        const userId = user.id;
        const name = user.name;
        const email = user.email;

        const accessToken = jwt.sign({ userId, name, email }, process.env.ACCSES_TOKEN_SECRET, { expiresIn: '1m' });
        const refreshToken = jwt.sign({ userId, name, email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1d' });

        await Users.update({ refresh_token: refreshToken }, {
            where: {
                id: userId
            }
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000
        });
        res.json({ accessToken });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const Logout = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;  
    if (!refreshToken) return res.sendstatus(204);
    const user = await Users.findOne({ 
        where: { 
            refresh_token: refreshToken 
        } 
     });
    if (!user) return res.sendstatus(204);
    const userId = user.id;
    await Users.update({ refresh_token: null }, {
        where: {
            id: userId
        }
    });
    res.clearCookie('refreshToken');    
    res.sendStatus(200);
}
