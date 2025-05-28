const express = require('express');
const router = express.Router();

// GET /movies/search
router.get("/search", async (req, res) => {
    let { title = "", year = "", page = "1" } = req.query;

    // Validate allowed query params
    const allowedParams = ['title', 'year', 'page'];
    const queryParams = Object.keys(req.query);
    for (const key of queryParams) {
        if (!allowedParams.includes(key)) {
            return res.status(400).json({ error: true, message: "Invalid query parameter provided." });
        }
    }

    // Validate year
    if (year && !/^\d{4}$/.test(year)) {
        return res.status(400).json({ error: true, message: "Invalid year format. Format must be yyyy." });
    }

    // Validate page
    if (!/^\d+$/.test(page)) {
        return res.status(400).json({ error: true, message: "Invalid page format. page must be a number." });
    }
    page = parseInt(page);

    try {
        // Query the database
        let query = req.db
            .from("movies.basics")
            .select(
                "primaryTitle AS title",
                "year",
                "tconst AS imdbID",
                "imdbRating",
                "rottentomatoesRating AS rottenTomatoesRating",
                "metacriticRating",
                "rated AS classification"
            );

        if (title) {
            query = query.whereILike('primaryTitle', `%${title}%`);
        }
        if (year) {
            query = query.where('year', year);
        }

        const rows = await query;

        // Pagination
        const perPage = 100;
        const resultLength = rows.length;
        const lastPage = Math.ceil(resultLength / perPage);
        const startIndex = (page - 1) * perPage;
        const endIndex = startIndex + perPage;
        const slicedRows = rows.slice(startIndex, endIndex);

        // Convert ratings to correct types
        slicedRows.forEach(element => {
            element.imdbRating = element.imdbRating !== null ? parseFloat(element.imdbRating) : null;
            element.rottenTomatoesRating = element.rottenTomatoesRating !== null ? parseInt(element.rottenTomatoesRating) : null;
            element.metacriticRating = element.metacriticRating !== null ? parseInt(element.metacriticRating) : null;
        });

        // Pagination object
        const pagination = {
            total: resultLength,
            lastPage: lastPage,
            prevPage: page > 1 && page > lastPage ? lastPage : (page > 1 && page <= lastPage ? page - 1 : null),
            nextPage: page < lastPage ? page + 1 : null,
            perPage: perPage,
            currentPage: page,
            from: resultLength === 0 ? 0 : startIndex,
            to: resultLength === 0 ? 0 : startIndex + slicedRows.length
        };

        res.json({
            data: slicedRows,
            pagination: pagination
        });
    } catch (err) {
        res.status(500).json({ error: true, message: "Error with database" });
    }
});

// GET /movies/data/:imdbID
router.get("/data/:imdbID", async (req, res) => {
    const imdbID = req.params.imdbID;

    // No query params allowed
    if (Object.keys(req.query).length !== 0) {
        return res.status(400).json({ error: true, message: "Query parameters are not permitted." });
    }

    try {
        // Get movie data
        const movieDataArr = await req.db
            .from("movies.basics")
            .select(
                "primaryTitle AS title",
                "year",
                "runtimeMinutes AS runtime",
                "genres",
                "country",
                "boxoffice",
                "poster",
                "plot",
                "imdbRating",
                "rottentomatoesRating",
                "metacriticRating"
            )
            .where("tconst", imdbID);

        if (movieDataArr.length === 0) {
            return res.status(404).json({ error: true, message: "Movie not found" });
        }

        let result = movieDataArr[0];
        result.genres = result.genres ? result.genres.split(',') : [];

        // Ratings array
        result.ratings = [
            { source: "Internet Movie Database", value: result.imdbRating !== null ? parseFloat(result.imdbRating) : null },
            { source: "Rotten Tomatoes", value: result.rottentomatoesRating !== null ? parseInt(result.rottentomatoesRating) : null },
            { source: "Metacritic", value: result.metacriticRating !== null ? parseInt(result.metacriticRating) : null }
        ];
        delete result.imdbRating;
        delete result.rottentomatoesRating;
        delete result.metacriticRating;

        // Principals (cast/crew)
        const principals = await req.db
            .from("movies.principals")
            .select("nconst AS id", "category", "name", "characters")
            .where("tconst", imdbID);

        // Parse characters array
        principals.forEach(element => {
            if (element.characters) {
                element.characters = element.characters.replace(/[\[\]"]/g, '').split(',').filter(c => c);
            } else {
                element.characters = [];
            }
        });

        result.principals = principals;

        res.json(result);
    } catch (err) {
        res.status(404).json({ error: true, message: "Error with database" });
    }
});

module.exports = router;