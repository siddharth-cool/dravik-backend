import { User } from "../server"; // Optional if you have a User type

declare global {
  namespace Express {
    interface Request {
      user?: any; // or your User interface
    }
  }
}
