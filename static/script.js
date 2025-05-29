document.getElementById('infoForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent form submission

    const inputField = document.getElementById('inputField').value;
    const infoType = document.getElementById('infoType').value;

    // Show the spinner
    showSpinner();

    fetch(`/api/info?input=${inputField}&type=${infoType}`)
        .then(response => response.json())
        .then(data => {
            displayResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            displayError('An error occurred while fetching the data.');
        })
        .finally(() => {
            // Hide the spinner
            hideSpinner();
        });
});

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = ''; // Clear previous results

    if (data.error) {
        displayError(data.error);
        return;
    }

    // Create a structured layout for the results
    const resultTable = document.createElement('table');
    resultTable.classList.add('result-table');

    for (const [key, value] of Object.entries(data)) {
        const row = document.createElement('tr');
        
        const keyCell = document.createElement('td');
        keyCell.classList.add('key-cell');
        keyCell.textContent = capitalizeFirstLetter(key);

        const valueCell = document.createElement('td');
        valueCell.classList.add('value-cell');

        if (Array.isArray(value)) {
            valueCell.innerHTML = formatArray(value);
        } else if (typeof value === 'object') {
            valueCell.innerHTML = formatNestedObject(value);
        } else {
            valueCell.textContent = value;
        }

        row.appendChild(keyCell);
        row.appendChild(valueCell);
        resultTable.appendChild(row);
    }

    resultsDiv.appendChild(resultTable);
}

function displayError(message) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `<p class="error">${message}</p>`;
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function formatNestedObject(obj) {
    let formatted = '<ul>';
    for (const [key, value] of Object.entries(obj)) {
        formatted += `<li><strong>${capitalizeFirstLetter(key)}:</strong> `;
        if (Array.isArray(value)) {
            formatted += formatArray(value);
        } else if (typeof value === 'object') {
            formatted += formatNestedObject(value);
        } else {
            formatted += value;
        }
        formatted += '</li>';
    }
    formatted += '</ul>';
    return formatted;
}

function formatArray(arr) {
    let formatted = '<ul>';
    arr.forEach(item => {
        if (typeof item === 'object') {
            formatted += `<li>${formatNestedObject(item)}</li>`;
        } else {
            formatted += `<li>${item}</li>`;
        }
    });
    formatted += '</ul>';
    return formatted;
}

// Spinner functionality
function showSpinner() {
    const spinner = document.getElementById('loading');
    spinner.style.display = 'flex'; // Ensure the spinner is visible
}

function hideSpinner() {
    const spinner = document.getElementById('loading');
    spinner.style.display = 'none'; // Hide the spinner
}
