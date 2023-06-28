
const User = require("../models/User");
const { SECRET } = require("../config");
const { Strategy, ExtractJwt } = require("passport-jwt");

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: SECRET
};

module.exports = (passport) => {
  passport.use(
    new Strategy(opts, async (payload, done) => {
      try {
        console.log("payload  - ", payload)
      
        const user = await User.findOne({email:payload.email});
       
        if (user) {
          user.role = [user.role]; 
          return done(null, user);
        }
        return done(null, false);
      } catch (err) {
        return done(err, false);
      }
    })
  );
};
