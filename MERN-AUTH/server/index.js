import 'dotenv/config';
import express  from 'express';
import cors from 'cors';
import cookieParser  from 'cookie-parser';
import userRouter from './routes/userRoutes.js';


import connectDB from './config/mongodb.js'
import authRouter  from './routes/authRoutes.js';

const allowedOrigins = ['http://localhost:5173'];

const app = express();
const PORT = process.env.PORT || 9000
connectDB();
app.use(express.json());
app.use(cookieParser());
app.use(cors({origin: allowedOrigins, credentials: true}));



//api end points 
app.get('/',(req,res) =>{
    res.send('welcome to mr hemant')
})
app.use('/api/auth' , authRouter)

app.use('/api/user' , userRouter)

app.listen(PORT,() =>{
    console.log(`server is running on port: ${PORT}`);
    
})