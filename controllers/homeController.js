const BigPromise = require("../middlewares/bigPromise");

exports.home = BigPromise(async (req, res) => {
  // const db  = await something()
  res.status(200).json({
    success: true,
    greeting: "hello from API",
  });
});

// Either use the above way of BigPromise or the below way of using sync await along with try catch or may be 3rd one - use promises wherever required

exports.homeDummy = async (req, res) => {
  try {
    // const db  = await something()

    res.status(200).json({
      success: true,
      greeting: "this is another dummy route",
    });
  } catch (error) {
      console.log(error);
  }
};
