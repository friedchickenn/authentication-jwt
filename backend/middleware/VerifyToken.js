import jwt from 'jsonwebtoken'; 

export const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ message: "Access Denied" });
    jwt.verify(token, process.env.ACCSES_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Token is not valid" });
        req.email = decoded.email;
        next();
    })
}