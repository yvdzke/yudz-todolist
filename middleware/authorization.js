const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = async (req, res, next) => {
  try {
    // 1. Ambil token dari header request (nama headernya 'jwt_token')
    const jwtToken = req.header("jwt_token");

    // 2. Kalau gak ada token, tolak!
    if (!jwtToken) {
      return res.status(403).json("Akses ditolak: Tidak ada token!");
    }

    // 3. Verifikasi token (Asli atau Palsu?)
    const payload = jwt.verify(jwtToken, process.env.JWT_SECRET);

    // 4. Kalau asli, simpan data user (user_id) ke dalam req.user
    req.user = payload;

    // 5. Lanjut ke proses berikutnya (Routes)
    next();
  } catch (err) {
    console.error(err.message);
    return res.status(403).json("Token tidak valid!");
  }
};
