import userModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
   try {
    const userId = req.user._id; // Assuming user ID is stored in req.user
    const user = await userModel.findById(userId);
    if (!user) {
        return res.json({
            success: false,
            message: "User not found"
        });
    }

    return res.json({
        success: true,
        userData:{
            name: user.name,
            isVerified: user.isVerified,
          
        }
    });
   } catch (error) {
       return res.json({
           success: false,
           message: error.message
       });
   }
}