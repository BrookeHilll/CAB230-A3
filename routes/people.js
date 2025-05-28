const express = require('express');
const router = express.Router();
const authorisation = require("../middleware/authorization");

// GET /people/:id
router.get('/:id', authorisation, async (req, res) => {
    const id = req.params.id;

    // No query params allowed
    if (Object.keys(req.query).length !== 0) {
        return res.status(400).json({ error: true, message: "Query parameters are not permitted." });
    }

    try {
        // Get person data
        const personArr = await req.db
            .from("movies.people")
            .select(
                "nconst AS id",
                "primaryName AS name",
                "birthYear",
                "deathYear"
            )
            .where("nconst", id);

        if (personArr.length === 0) {
            return res.status(404).json({ error: true, message: "Person not found" });
        }

        let person = personArr[0];

        // Get known for movies
        const knownForArr = await req.db
            .from("movies.knownfor")
            .select("tconst AS imdbID")
            .where("nconst", id);

        person.knownForTitles = knownForArr.map(row => row.imdbID);

        // Get roles
        const rolesArr = await req.db
            .from("movies.principals")
            .select("tconst AS imdbID", "category", "characters")
            .where("nconst", id);

        // Parse characters array
        rolesArr.forEach(role => {
            if (role.characters) {
                role.characters = role.characters.replace(/[\[\]"]/g, '').split(',').filter(c => c);
            } else {
                role.characters = [];
            }
        });

        person.roles = rolesArr;

        res.json(person);
    } catch (err) {
        res.status(500).json({ error: true, message: "Error with database" });
    }
});

module.exports = router;