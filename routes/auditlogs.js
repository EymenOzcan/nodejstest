var express = require("express");
var router = express.Router();

/* GET users listing. */
router.get("/:id", (req, res, next) => {
  res.json({
    body: req.body,
    params: req.params,
    query: req.query,
    headers: req.headers,
  });
});

module.exports = router;
