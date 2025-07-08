import jwt from 'jsonwebtoken';

const userAuth = (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ success: false, message: "Not authenticated. Please login again." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (!decoded.id) {
            return res.status(401).json({ success: false, message: "Invalid token. Login again." });
        }

        // ✅ Recommended: Attach user info to req.user instead of req.body
        req.user = { id: decoded.id };

        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: "Token expired or invalid." });
    }
};

export default userAuth;
