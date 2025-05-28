module.exports = (dateString) => {
    // Split the date into its components
    const [year, month, day] = dateString.split('-');

    // Convert the components into numbers
    const numericYear = parseInt(year, 10);
    const numericMonth = parseInt(month, 10);
    const numericDay = parseInt(day, 10);

    // Check if the date is in the future
    const currentDate = new Date();
    const date = new Date(numericYear, numericMonth, numericDay);
    if (date > currentDate) {
        return false; // Date is in the future
    }

    return true; // Date is not in the future
}