<?php
require 'config.php';
?>

<html>
<head>
    <title><?php echo $blog_config['title'] ?></title>
    <link rel="stylesheet" href="<?php echo $env_config['root_path'];?>/views/element/element.css">
    <script src="<?php echo $env_config['root_path'];?>/views/element/vue.min.js"></script>
    <script src="<?php echo $env_config['root_path'];?>/views/element/vue-resource.min.js"></script>
    <script src="<?php echo $env_config['root_path'];?>/views/element/element.js"></script>
</head>
<body>
    <div class="container" id="app">
        <el-form label-width="100px" :label-position="labelPosition">
            <el-form-item label="Password:">
                <el-input v-model="formLabelAlign.password" placeholder="Please input password to show the article:" type="password" name="password"></el-input>
            </el-form-item>
            <el-form-item>
                <el-button type="primary" @click="submitForm()">Verify</el-button>
            </el-form-item>
        </el-form>
    </div>
    <script>
        new Vue({
            el: '#app',
            data() {
                return {
                    labelPosition: 'left',
                    formLabelAlign: {
                        password: ''
                    }
                };
            },
            computed:{
                formData() {
                    return {
                        password: this.formLabelAlign.password
                    };
                }
            },
            methods: {
                submitForm() {
                    this.$http.post("<?php echo $env_config['root_path']; ?>/show.php?id=<?php echo $data['post']['id'];?>", this.formData).then(function(response) {
                        this.$message({
                            duration: 1500,
                            message: 'Password correct.',
                            type: 'success',
                            onClose: function() {
                                document.write(response.body);
                            }
                        });
                    }, function() {
                        this.$message({
                            duration: 1500,
                            message: 'Password incorrect!!!',
                            type: 'error'
                        });
                    });
                }
            },
            http: {
                emulateJSON: true,
                emulateHTTP: true
            }
        });
    </script>
</body>
</html>
