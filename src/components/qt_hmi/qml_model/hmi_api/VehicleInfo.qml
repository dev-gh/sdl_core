import QtQuick 2.0

Item {
    function isReady () {
        return {
            available: dataContainer.hmiVehicleInfoAvailable
        }
    }

    function getVehicleType() {
        return {
            make: "Ford",
            model: "Fiesta",
            modelYear: "2013",
            trim: "SE"
        }
    }
}
