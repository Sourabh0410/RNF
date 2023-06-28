const router = require("express").Router();


const {
  refreshToken,
  userAuth,
  userLogin,
  checkRole,
  userRegister,
  getStudents,
  getTeachers
  
} = require("../utils/Auth");

// Users Registeration Route
router.post("/register", async (req, res) => {
 let role=req.body.role
  await userRegister(req.body, role, res);
});



// Users Login Route
router.post("/login", async (req, res) => {
  let role=req.body.role
  
  await userLogin(req.body, role, res);
});

// Users Refresh-Token Route
router.post("/refresh-token", async (req, res) => {
  const token = req.body.token;

  await refreshToken(token, res);
});

// Users Get Student Route
router.get('/students', userAuth, checkRole(['student']),getStudents);


// Users Get Teacher Route
router.get('/teachers', userAuth, checkRole(['teacher']),getTeachers);

module.exports = router;
