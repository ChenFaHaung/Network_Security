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
        This feature is demo-oriented... You are just a read-only user.
        <el-form label-width="100px" :label-position="labelPosition">
            <el-form-item label="Title">
                <el-input v-model="formLabelAlign.title" placeholder="Title" name="title"></el-input>
            </el-form-item>
            <el-form-item label="Password">
                <el-input v-model="formLabelAlign.password" placeholder="Password" type="password" name="password"></el-input>
            </el-form-item>
            <el-form-item label="Content">
                <el-input v-model="formLabelAlign.content" placeholder="Content" name="content"></el-input>
            </el-form-item>
            <el-form-item>
                <el-button type="primary" @click="submitForm()" disabled>Create Post</el-button>
            </el-form-item>
        </form>
    </div>
    <script>
        new Vue({
            el: '#app',
            data() {
                return {
                    labelPosition: 'left',
                    formLabelAlign: {
                        title: '',
                        password: '',
                        content: ''
                    }
                };
            },
            computed:{
                formData() {
                    return {
                        title: this.formLabelAlign.title,
                        password: this.formLabelAlign.password,
                        content: this.formLabelAlign.content
                    };
                }
            },
            methods: {
                submitForm() {
                    this.$http.post("<?php echo $env_config['root_path']; ?>/create.php", this.formData).then(function(response) {
                        this.$message({
                            duration: 1500,
                            message: 'Congrat! Form is submitted.',
                            type: 'success',
                            onClose: function() {
                                window.location = '/';
                            }
                        });
                    }, function() {
                        this.$message({
                            duration: 1500,
                            message: 'Failed! Title and content cannot be blank!',
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
