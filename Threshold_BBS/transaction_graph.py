import matplotlib.pyplot as plt
import numpy as np

# Schemes (x-axis labels)
schemes = ['RP-Coconut', 'Threshold BBS', 'Threshold BBS+']

# Gas consumption data for different functions (y-axis values)
PublishPublicParams = [132775, 61841, 61841]
VerifyRequestZKP = [785514, 459579, 459579]
PublishPartialCredential = [113841, 39550, 40319]
VerifyCredentialZKP = [1534253, 764980, 790651]

# Position of bars on the x-axis
x = np.arange(len(schemes))
bar_width = 0.2  # Set bar width for better visibility

# Plot the stacked bar chart with optimized colors and hatching
plt.bar(
    x, VerifyCredentialZKP, 
    width=bar_width, 
    bottom=np.array(PublishPublicParams) + np.array(VerifyRequestZKP) + np.array(PublishPartialCredential), 
    label='VerifyCredential', hatch='///', color='#aec7e8'  # Light blue
)
plt.bar(
    x, PublishPartialCredential, 
    width=bar_width, 
    bottom=np.array(PublishPublicParams) + np.array(VerifyRequestZKP), 
    label='IssueCredential', hatch='||||', color='#ffbb78'  # Soft orange
)
plt.bar(
    x, VerifyRequestZKP, 
    width=bar_width, 
    bottom=PublishPublicParams, 
    label='RequestCredential', hatch='...', color='#98df8a'  # Light green
)
plt.bar(
    x, PublishPublicParams, 
    width=bar_width, 
    label='SetupPublicParams', hatch='xxxx', color='#c5b0d5'  # Soft purple
)

# Add labels, title, and legend with larger font sizes
plt.xlabel('Schemes', fontsize=16)  # Increase font size for x-axis label
plt.ylabel('Gas Consumption', fontsize=16)  # Increase font size for y-axis label
plt.xticks(x, schemes, fontsize=12)  # Increase font size for x-axis tick labels

# Adjust y-axis labels
plt.ylim(0, 2700000)  # Set the y-axis limit
plt.yticks(
    np.arange(0, 2700001, 250000),  # Tick positions
    [f'{int(value):,}' for value in np.arange(0, 2700001, 250000)],  # Tick labels in standard format
    fontsize=12  # Increase font size for y-axis ticks
)

# Add legend with increased font size
plt.legend(fontsize=12)

# Save the graph in SVG format
plt.tight_layout()
plt.savefig("stacked_bar_transaction_graph.svg", format='svg')  # Save as SVG
plt.show()
