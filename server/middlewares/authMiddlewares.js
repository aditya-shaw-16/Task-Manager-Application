import jwt from "jsonwebtoken"
import User from "../models/user.js"
const protectRoute = async(req, res, next) => {
    try{
        let token = req.cookie.token;

        if(token){
            const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

            const resp = await User.findById(decodedToken.userId).select(
                "isAdmin email"
            );

            req.user = {
                email: resp.email,
                isAdmin: resp.isAdmin,
                userId: decodedToken.userId,
            };

            next();
        }
    } catch(error){
        console.log(error);
        return res
            .status[401]
            .json({status: false, message: "Not authorised. Try loging Again."});
    }
};

const isAdminRoute = (req,res, next) => {
    if(req.user && req.user.isAdmin){
        next();
    } else {
        return res.status(401).json({
            status: false,
            message: "You are not an admin. Try logging in with admin credentials",
        });
    }
};

export {isAdminRoute, protectRoute};