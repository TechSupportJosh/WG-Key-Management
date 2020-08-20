// Modified from https://stackoverflow.com/questions/20618355/the-simplest-possible-javascript-countdown-timer
function startTimer(connectionRequestId, duration) {
    var start = Date.now(),
        diff,
        minutes,
        seconds;
    
    let display = document.getElementById(`connectionRequestTimer-${connectionRequestId}`);

    let timerId;

    function timer() {
        // get the number of seconds that have elapsed since 
        // startTimer() was called
        diff = duration - (((Date.now() - start) / 1000) | 0);

        // does the same job as parseInt truncates the float
        minutes = (diff / 60) | 0;
        seconds = (diff % 60) | 0;

        minutes = minutes < 10 ? "0" + minutes : minutes;
        seconds = seconds < 10 ? "0" + seconds : seconds;

        display.textContent = minutes + ":" + seconds; 

        if (diff <= 0) {
            // add one second so that the count down starts at the full duration
            // example 05:00 not 04:59
            start = Date.now() + 1000;
        }
        
        if(minutes <= 0 && seconds <= 0)
        {
            // Timer has finished, stop the timer function
            clearInterval(timerId);

            // Then update the button to display Request Expired
            document.getElementById(`connectionRequestButton-${connectionRequestId}`).innerHTML = "<strong>Request Expired</strong>";
        }
    };
    // we don't want to wait a full second before the timer starts
    timer();
    timerId = setInterval(timer, 1000);
}

window.onload = function () {
    connectionRequestTimes.forEach(request => {
        // For each request, calculate seconds until expiryTime
        let timerLength = request.expiryTime - Math.floor(Date.now() / 1000);
        startTimer(request.id, timerLength)
    });
};